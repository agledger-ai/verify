/**
 * Key anchoring on the dump path: every row a vault key signs (chain entries,
 * vault checkpoints, read-log leaves, read-log tree heads) is graded against
 * verify-core's walk of the dump's key statements from `trustAnchors`, with the
 * engine's codes, and a run without anchors is never a clean verdict.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { verifyDump } from '../src/dump-verifier.js';
import { DEFAULT_FILENAMES, loadDump } from '../src/loader.js';
import { EXIT_CANNOT_VERIFY, EXIT_VERIFICATION_FAILED, runCli } from '../src/cli.js';
import type { Dump, FailureCode, VerifyReport } from '../src/types.js';
import {
  buildHappyDump,
  buildOrgAdminRead,
  buildOrgAdminReadsCheckpoint,
  buildVaultCheckpoint,
  generateKey,
  pinOf,
  signingKeyDump,
} from './fixtures.js';

const VALID = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'conformance', 'dump', 'valid');
const VALID_PIN = 'sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e';

function codes(report: VerifyReport): FailureCode[] {
  return [
    ...report.vault.failures.map((f) => f.code),
    ...report.orgAdminReads.failures.map((f) => f.code),
    ...report.keyTrust.findings.map((f) => f.code),
  ];
}

/**
 * The happy dump plus what a writer with database access and no vault key can
 * add: a key row of its own, and a vault checkpoint, a read-log leaf and a
 * read-log tree head signed with it. No statement admits the key.
 */
function planted(): { dump: Dump; pin: string } {
  const { dump, key } = buildHappyDump();
  const rogue = generateKey();
  dump.signingKeys.push(signingKeyDump(rogue));
  const cp = dump.vaultCheckpoints[0]!;
  const resigned = buildVaultCheckpoint('record-bbbb', cp.chain_position, cp.payload_hash, rogue);
  dump.vaultCheckpoints = [{ ...cp, cose_sign1: resigned.cose_sign1, signing_key_id: resigned.signing_key_id }];
  const org1 = dump.orgAdminReads.filter((l) => l.org_id === 'enterprise-1');
  dump.orgAdminReadsCheckpoints = [buildOrgAdminReadsCheckpoint('enterprise-1', org1, rogue, org1.length)];
  dump.orgAdminReads.push(buildOrgAdminRead({ orgId: 'enterprise-2', leafIndex: 1, key: rogue }));
  return { dump, pin: pinOf(key) };
}

describe('rows signed by a key no statement anchors', () => {
  it('pinned, each fails with the code the engine reports for it', () => {
    const { dump, pin } = planted();
    const report = verifyDump(dump, { trustAnchors: [pin] });
    expect(report.verdict).toBe('failed');
    expect(codes(report).sort()).toEqual([
      'CHECKPOINT_KEY_UNANCHORED',
      'TENANT_CHECKPOINT_KEY_UNANCHORED',
      'TENANT_READ_KEY_UNANCHORED',
    ]);
    expect(report.keyTrust.unanchoredKeyIds).toHaveLength(1);
    expect(report.vault.optionalChecks.key_anchoring).toBe('applied');
  });

  it('unpinned, the same dump finds nothing wrong, which is why the pass is flagged unanchored', () => {
    const report = verifyDump(planted().dump);
    expect(codes(report)).toEqual([]);
    expect(report).toMatchObject({ ok: true, verdict: 'unanchored', keyTrust: { status: 'no_anchor' } });
    expect(report.vault.optionalChecks.key_anchoring).toBe('skipped_no_input');
  });
});

describe('the key statements themselves', () => {
  it('a statement whose signature does not verify fails the dump, though every chain holds', () => {
    const dump = loadDump(VALID);
    const st = dump.keyStatements[0]!;
    const bytes = Buffer.from(st.statement[0]!, 'base64');
    bytes[bytes.length - 1] = (bytes[bytes.length - 1]! ^ 0xff) & 0xff;
    st.statement[0] = bytes.toString('base64');
    const report = verifyDump(dump, { trustAnchors: [VALID_PIN] });
    expect(report.verdict).toBe('failed');
    expect(report.keyTrust.findings.map((f) => f.code)).toContain('KEY_STATEMENT_INVALID');
  });

  it('a pinned run over the unmodified dump walks them in write order', () => {
    const report = verifyDump(loadDump(VALID), { trustAnchors: [VALID_PIN] });
    expect(report).toMatchObject({ ok: true, verdict: 'trusted', keyTrust: { status: 'walked', order: 'written' } });
  });

  it('a statement file the walk cannot order is refused: TypeError in the API, exit 2 on the CLI', () => {
    const dump = loadDump(VALID);
    const extra = { ...dump.keyStatements[0]!, id: 'no-write-time' } as Partial<Dump['keyStatements'][number]>;
    delete extra.created_at;
    dump.keyStatements.push(extra as Dump['keyStatements'][number]);
    expect(() => verifyDump(dump, { trustAnchors: [VALID_PIN] })).toThrow(TypeError);

    const dir = mkdtempSync(join(tmpdir(), 'agledger-verify-anchor-'));
    try {
      const files: Record<keyof typeof DEFAULT_FILENAMES, readonly unknown[]> = {
        vaultEntries: dump.vaultEntries,
        vaultCheckpoints: dump.vaultCheckpoints,
        signingKeys: dump.signingKeys,
        keyStatements: dump.keyStatements,
        orgAdminReads: dump.orgAdminReads,
        orgAdminReadsCheckpoints: dump.orgAdminReadsCheckpoints,
      };
      for (const [k, name] of Object.entries(DEFAULT_FILENAMES) as Array<[keyof typeof DEFAULT_FILENAMES, string]>) {
        writeFileSync(join(dir, name), files[k].map((r) => JSON.stringify(r)).join('\n') + '\n');
      }
      const r = runCli([dir, '--trust-anchor', VALID_PIN]);
      expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
      expect(r.stderr).toContain('createdAt');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('inputs', () => {
  it('distrustedKeys without trustAnchors is refused rather than ignored', () => {
    const { dump } = buildHappyDump();
    expect(() => verifyDump(dump, { distrustedKeys: [VALID_PIN] })).toThrow(/pass trustAnchors as well/);
  });

  it('a malformed anchor is refused', () => {
    const { dump } = buildHappyDump();
    expect(() => verifyDump(dump, { trustAnchors: ['15d63684'] })).toThrow(TypeError);
  });

  it('the CLI lists key-statement findings under key anchoring and exits 1', () => {
    const { dump, pin } = planted();
    const dir = mkdtempSync(join(tmpdir(), 'agledger-verify-anchor-'));
    try {
      const files: Record<keyof typeof DEFAULT_FILENAMES, readonly unknown[]> = {
        vaultEntries: dump.vaultEntries,
        vaultCheckpoints: dump.vaultCheckpoints,
        signingKeys: dump.signingKeys,
        keyStatements: dump.keyStatements,
        orgAdminReads: dump.orgAdminReads,
        orgAdminReadsCheckpoints: dump.orgAdminReadsCheckpoints,
      };
      for (const [k, name] of Object.entries(DEFAULT_FILENAMES) as Array<[keyof typeof DEFAULT_FILENAMES, string]>) {
        const lines = files[k].map((r) => JSON.stringify(r)).join('\n');
        writeFileSync(join(dir, name), lines + (lines ? '\n' : ''));
      }
      const r = runCli([dir, '--trust-anchor', pin]);
      expect(r.exitCode).toBe(EXIT_VERIFICATION_FAILED);
      expect(r.stdout).toMatch(/^\[FAIL\]/);
      expect(r.stdout).toMatch(/unanchored {2}: [0-9a-f]{16}/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
