import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { spkiSha256 } from '@agledger/verify-core';
import { DEFAULT_FILENAMES, loadDump } from '../src/loader.js';
import { verifyDump } from '../src/dump-verifier.js';
import { EXIT_OK, EXIT_VERIFICATION_FAILED, runCli } from '../src/cli.js';
import type { Dump, FailureCode, VerifyReport } from '../src/types.js';

/**
 * Row data no engine writes (a nulled, dropped or retyped column) is a failure
 * code, never a throw out of the walk and never a pass read off a skipped
 * check; and a pin over a dump with nothing signed by a key it anchors is not
 * a trusted pass. Every case is a mutation of a real corpus dump.
 */

const CONFORMANCE = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'conformance', 'dump');
const VALID = join(CONFORMANCE, 'valid');
const HISTORY = join(CONFORMANCE, 'valid-unsigned-history-then-signed');

function pinOf(dump: Dump): string {
  return `sha256:${spkiSha256(dump.signingKeys[0]!.public_key)}`;
}

function codes(report: VerifyReport): FailureCode[] {
  return [...new Set([...report.keyTrust.findings, ...report.vault.failures, ...report.orgAdminReads.failures].map((f) => f.code))].sort();
}

function writeDump(dump: Dump): string {
  const dir = mkdtempSync(join(tmpdir(), 'agledger-verify-malformed-'));
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
  return dir;
}

describe('a vault row with no readable created_at fails closed', () => {
  it('nulling every write time does not pass a distrusted key past its cutoff', () => {
    // Pinned on the current key; the key it succeeded is distrusted from just
    // before the entry that key signed.
    const succession = join(CONFORMANCE, 'valid-key-succession');
    const plain = loadDump(succession);
    const previous = plain.signingKeys.find((k) => k.status === 'retired')!;
    const current = plain.signingKeys.find((k) => k.status === 'active')!;
    const pin = `sha256:${spkiSha256(current.public_key)}`;
    const entry = plain.vaultEntries.find((e) => e.signing_key_id === previous.key_id)!;
    const cutoff = new Date(Date.parse(entry.created_at!) - 1).toISOString();
    const distrust = `sha256:${spkiSha256(previous.public_key)}@${cutoff}`;
    expect(codes(verifyDump(plain, { trustAnchors: [pin], distrustedKeys: [distrust] }))).toContain('CHAIN_KEY_EXPIRED');

    const dump = loadDump(succession);
    for (const e of dump.vaultEntries) (e as { created_at: unknown }).created_at = null;
    const report = verifyDump(dump, { trustAnchors: [pin], distrustedKeys: [distrust] });
    expect(report.verdict).toBe('failed');
    expect(codes(report)).toContain('CHAIN_MALFORMED_ENTRY');

    const dir = writeDump(dump);
    try {
      const r = runCli([dir, '--trust-anchor', pin, '--distrusted-key', distrust]);
      expect(r.exitCode).toBe(EXIT_VERIFICATION_FAILED);
      expect(r.stdout).toContain('Entry has no parseable createdAt, so it cannot be placed inside key');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a single-entry record with its key id and write time nulled is not unsigned history', () => {
    const dump = loadDump(VALID);
    const counts = new Map<string, number>();
    for (const e of dump.vaultEntries) counts.set(e.chain_key!, (counts.get(e.chain_key!) ?? 0) + 1);
    const lone = dump.vaultEntries.find((e) => counts.get(e.chain_key!) === 1);
    expect(lone).toBeDefined();
    (lone as { signing_key_id: unknown }).signing_key_id = null;
    (lone as { created_at: unknown }).created_at = null;
    dump.vaultCheckpoints = dump.vaultCheckpoints.filter((c) => c.chain_key !== lone!.chain_key);
    const report = verifyDump(dump, { trustAnchors: [pinOf(dump)] });
    expect(report.verdict).toBe('failed');
    expect(codes(report)).toEqual(['CHAIN_MALFORMED_ENTRY']);
  });
});

describe('malformed rows are failure codes, not throws', () => {
  const cases: Array<[string, (d: Dump) => void, FailureCode]> = [
    ['a null payload', (d) => { (d.vaultEntries[0] as { payload: unknown }).payload = null; }, 'CHAIN_PAYLOAD_BINDING_MISMATCH'],
    ['a dropped payload', (d) => { delete (d.vaultEntries[0] as { payload?: unknown }).payload; }, 'CHAIN_PAYLOAD_BINDING_MISMATCH'],
    ['a null public_key', (d) => { for (const k of d.signingKeys) (k as { public_key: unknown }).public_key = null; }, 'CHAIN_SIGNATURE_MISSING_KEY'],
    ['a retyped chain_key', (d) => { for (const e of d.vaultEntries) (e as { chain_key: unknown }).chain_key = 7; }, 'CHECKPOINT_ROW_MISSING'],
    ['a null checkpoint record_id', (d) => { for (const c of d.vaultCheckpoints) (c as { record_id: unknown }).record_id = null; }, 'CHECKPOINT_CLAIM_MISMATCH'],
    ['a null read-log record_id', (d) => { (d.orgAdminReads[0] as { record_id: unknown }).record_id = null; }, 'TENANT_READ_CLAIM_MISMATCH'],
    ['a null tree-head root_hash', (d) => { (d.orgAdminReadsCheckpoints[0] as { root_hash: unknown }).root_hash = null; }, 'TENANT_CHECKPOINT_ROOT_MISMATCH'],
    ['a null tree-head tree_size', (d) => { (d.orgAdminReadsCheckpoints[0] as { tree_size: unknown }).tree_size = null; }, 'TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH'],
    ['a null chain_position', (d) => { (d.vaultEntries[1] as { chain_position: unknown }).chain_position = null; }, 'CHAIN_POSITION_GAP'],
    ['a null leaf_index', (d) => { (d.orgAdminReads[0] as { leaf_index: unknown }).leaf_index = null; }, 'TENANT_READ_LEAF_INDEX_GAP'],
  ];
  for (const [name, mutate, code] of cases) {
    it(`${name} fails ${code}`, () => {
      const dump = loadDump(VALID);
      const pin = pinOf(dump);
      mutate(dump);
      for (const options of [{}, { trustAnchors: [pin] }]) {
        const report = verifyDump(dump, options);
        expect(report.verdict).toBe('failed');
        expect(codes(report)).toContain(code);
      }
    });
  }
});

describe('a pin over a dump with nothing signed under a key it anchors', () => {
  it('is no_anchored_signature: a pass, never a trusted one', () => {
    const dump = loadDump(HISTORY);
    // Keep only the vault history written before the install registered its
    // key: the unsigned entries and their unsigned checkpoint, no read log and
    // no statements, as an install that has signed nothing yet dumps.
    dump.vaultEntries = dump.vaultEntries.filter((e) => e.signing_key_id === null);
    dump.vaultCheckpoints = dump.vaultCheckpoints.filter((c) => c.signing_key_id === null);
    dump.orgAdminReads = [];
    dump.orgAdminReadsCheckpoints = [];
    dump.keyStatements = [];
    const report = verifyDump(dump, { trustAnchors: [`sha256:${'a'.repeat(64)}`] });
    expect(report.ok).toBe(true);
    expect(report.verdict).toBe('unanchored');
    expect(report.keyTrust.status).toBe('no_anchored_signature');
    expect(report.vault.signedEntries).toBe(0);
    expect(report.vault.optionalChecks.key_anchoring).toBe('not_checked');

    const dir = writeDump(dump);
    try {
      const r = runCli([dir, '--trust-anchor', `sha256:${'a'.repeat(64)}`]);
      expect(r.exitCode).toBe(EXIT_OK);
      expect(r.stdout).toContain('[VERIFIED, NOT ANCHORED] AGLedger offline verification (dump)');
      expect(r.stdout).toContain('the --trust-anchor was walked, but no');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('unsigned history followed by entries signed under the anchored key is trusted', () => {
    const dump = loadDump(HISTORY);
    const report = verifyDump(dump, { trustAnchors: [pinOf(dump)] });
    expect(report.verdict).toBe('trusted');
    expect(report.keyTrust.status).toBe('walked');
    expect(report.vault.optionalChecks.key_anchoring).toBe('applied');
  });
});
