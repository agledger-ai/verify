import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_FILENAMES } from '../src/loader.js';
import {
  EXIT_CANNOT_VERIFY,
  EXIT_OK,
  EXIT_UNANCHORED,
  EXIT_VERIFICATION_FAILED,
  formatDumpReportText,
  formatExportReportText,
  parseArgs,
  runCli,
} from '../src/cli.js';
import { verifyDump } from '../src/dump-verifier.js';
import { reportKeyTrust, type VerifyExportResult } from '@agledger/verify-core';
import { buildHappyDump, cloneDump, pinOf } from './fixtures.js';

/** Minimal clean export result; tests override only the field under test. */
function exportResult(overrides: Partial<VerifyExportResult> = {}): VerifyExportResult {
  return {
    valid: true,
    totalEntries: 10,
    verifiedEntries: 10,
    entries: [],
    recordId: 'rec-1',
    signatureCoverage: { signed: 10, unsigned: 0, skipped: 0, total: 10 },
    optionalChecks: {
      payload_binding: 'applied',
      oidc_actor: 'applied',
      actor_attribution: 'applied',
      key_temporal: 'applied',
      agent_signature: 'skipped_no_input',
      key_anchoring: 'skipped_no_input',
    },
    keyProvenance: { supplied: 10, embedded: 0 },
    unsignedProjectionFields: [],
    agentSignatures: { present: 0, verified: 0 },
    keyTrust: reportKeyTrust(new Map(), null, null),
    ...overrides,
  };
}

describe('parseArgs', () => {
  const parsedDefaults = {
    keys: null,
    requireKeyId: null,
    requireSuppliedKeys: false,
    agentKeys: null,
    trustAnchors: [],
    distrustedKeys: [],
  };

  it('captures target and defaults to text report format', () => {
    expect(parseArgs(['/tmp/dump'])).toEqual({
      target: '/tmp/dump',
      reportFormat: 'text',
      showHelp: false,
      ...parsedDefaults,
    });
  });

  it('accepts --report-format json', () => {
    expect(parseArgs(['/tmp/dump', '--report-format', 'json'])).toEqual({
      target: '/tmp/dump',
      reportFormat: 'json',
      showHelp: false,
      ...parsedDefaults,
    });
  });

  it('accepts --report-format=json', () => {
    expect(parseArgs(['/tmp/dump', '--report-format=json'])).toEqual({
      target: '/tmp/dump',
      reportFormat: 'json',
      showHelp: false,
      ...parsedDefaults,
    });
  });

  it('rejects an unknown flag', () => {
    expect(() => parseArgs(['--bogus'])).toThrow(/Unknown flag/);
  });

  it('rejects two positional targets', () => {
    expect(() => parseArgs(['/a', '/b'])).toThrow(/Unexpected positional/);
  });

  it('rejects an unknown report format', () => {
    expect(() => parseArgs(['/tmp/dump', '--report-format', 'yaml'])).toThrow(/--report-format must be/);
  });

  it('captures the key-policy flags (verify#8)', () => {
    expect(
      parseArgs(['export.json', '--keys', 'keys.json', '--require-key-id=abc', '--require-supplied-keys']),
    ).toEqual({
      ...parsedDefaults,
      target: 'export.json',
      reportFormat: 'text',
      showHelp: false,
      keys: 'keys.json',
      requireKeyId: 'abc',
      requireSuppliedKeys: true,
    });
  });

  it('collects every --trust-anchor and --distrusted-keys, in either form', () => {
    const a = `sha256:${'a'.repeat(64)}`;
    const b = `sha256:${'b'.repeat(64)}`;
    expect(parseArgs(['/d', '--trust-anchor', a, `--trust-anchor=${b}`, '--distrusted-keys', `${b}@2026-09-01T00:00:00Z`])).toMatchObject({
      trustAnchors: [a, b],
      distrustedKeys: [`${b}@2026-09-01T00:00:00Z`],
    });
    expect(() => parseArgs(['/d', '--trust-anchor'])).toThrow(/--trust-anchor requires a value/);
  });

  it('names the renamed --require-out-of-band-keys flag', () => {
    expect(() => parseArgs(['e.json', '--require-out-of-band-keys'])).toThrow(/--require-supplied-keys/);
  });

  it('rejects --keys without a value', () => {
    expect(() => parseArgs(['export.json', '--keys'])).toThrow(/--keys requires a value/);
    expect(() => parseArgs(['export.json', '--keys', '--require-supplied-keys'])).toThrow(/--keys requires a value/);
  });
});

describe('formatDumpReportText', () => {
  it('renders a PASS header for a clean dump pinned on its key', () => {
    const { dump, key } = buildHappyDump();
    const text = formatDumpReportText(verifyDump(dump, { trustAnchors: [pinOf(key)] }));
    expect(text).toMatch(/^\[PASS\]/);
    expect(text).toContain(`walked from ${pinOf(key)}`);
    expect(text).toContain('audit_vault chain');
    expect(text).toContain('org_admin_reads chain');
  });

  it('never renders PASS for a clean dump verified without a pin', () => {
    const { dump } = buildHappyDump();
    const text = formatDumpReportText(verifyDump(dump));
    expect(text).toMatch(/^\[NOT ANCHORED\]/);
    expect(text).not.toContain('[PASS]');
    expect(text).toContain('NOT a clean verdict');
    expect(text).toContain('status      : NOT RUN');
  });

  it('renders a FAIL header and lists failure codes', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.vaultEntries[1]!.payload_hash = 'ff'.repeat(32);
    const text = formatDumpReportText(verifyDump(tampered));
    expect(text).toMatch(/^\[FAIL\]/);
    expect(text).toContain('CHAIN_HASH_MISMATCH');
  });
});

describe('formatExportReportText: unsigned-projection note', () => {
  it('warns that a PASS does not vouch for unsigned display projections', () => {
    const text = formatExportReportText(
      exportResult({ unsignedProjectionFields: ['actorDisplayName', 'actorOwnerType', 'humanReadableLabel'] }),
    );
    expect(text).toMatch(/^\[NOT ANCHORED\]/);
    expect(text).toContain('note');
    expect(text).toContain('actorDisplayName');
    expect(text).toContain('NOT signature-covered');
    expect(text).toContain('actorOwnerId'); // points at the signed identity
  });

  it('emits no note when the export carries no unsigned-projection guidance', () => {
    const text = formatExportReportText(exportResult({ unsignedProjectionFields: [] }));
    expect(text).not.toContain('note');
    expect(text).not.toContain('NOT signature-covered');
  });
});

describe('runCli (dump-dir end-to-end)', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'agledger-verify-cli-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writeDump(dump: ReturnType<typeof buildHappyDump>['dump']): void {
    const map: Record<keyof typeof DEFAULT_FILENAMES, unknown[]> = {
      vaultEntries: dump.vaultEntries,
      vaultCheckpoints: dump.vaultCheckpoints,
      signingKeys: dump.signingKeys,
      keyStatements: dump.keyStatements,
      orgAdminReads: dump.orgAdminReads,
      orgAdminReadsCheckpoints: dump.orgAdminReadsCheckpoints,
    };
    for (const [key, filename] of Object.entries(DEFAULT_FILENAMES) as Array<
      [keyof typeof DEFAULT_FILENAMES, string]
    >) {
      const lines = map[key].map((r) => JSON.stringify(r)).join('\n');
      writeFileSync(join(dir, filename), lines + (lines ? '\n' : ''));
    }
  }

  it('prints help on --help and exits 0', () => {
    const result = runCli(['--help']);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('Usage:');
  });

  it('exits 2 (could not verify) with a usage message when target is missing', () => {
    const result = runCli([]);
    expect(result.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(result.stderr).toContain('Missing <target>');
  });

  it('exits 0 on a clean dump directory pinned on its key', () => {
    const { dump, key } = buildHappyDump();
    writeDump(dump);
    const result = runCli([dir, '--trust-anchor', pinOf(key)]);
    expect(result.exitCode).toBe(EXIT_OK);
    expect(result.stdout).toMatch(/^\[PASS\]/);
  });

  it('exits 3 on a clean dump directory with no pin, and the JSON says it is not ok', () => {
    const { dump } = buildHappyDump();
    writeDump(dump);
    const text = runCli([dir]);
    expect(text.exitCode).toBe(EXIT_UNANCHORED);
    expect(text.stdout).toMatch(/^\[NOT ANCHORED\]/);
    const json = runCli([dir, '-f', 'json']);
    expect(json.exitCode).toBe(EXIT_UNANCHORED);
    const parsed = JSON.parse(json.stdout) as { ok: boolean; verdict: string; keyTrust: { status: string } };
    expect(parsed).toMatchObject({ ok: false, verdict: 'unanchored', keyTrust: { status: 'no_anchor' } });
  });

  it('exits 1 when the pin reaches none of the keys that signed the dump', () => {
    const { dump } = buildHappyDump();
    writeDump(dump);
    const result = runCli([dir, '--trust-anchor', `sha256:${'0'.repeat(64)}`]);
    expect(result.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    for (const code of ['CHAIN_SIGNING_KEY_UNANCHORED', 'CHECKPOINT_KEY_UNANCHORED', 'TENANT_READ_KEY_UNANCHORED']) {
      expect(result.stdout).toContain(`[${code}]`);
    }
  });

  it('exits 2 on a malformed pin or a distrusted key without one, before reading anything', () => {
    const bad = runCli(['/nonexistent', '--trust-anchor', 'abc', '-f', 'json']);
    expect(bad.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect((JSON.parse(bad.stdout) as { error: { message: string } }).error.message).toMatch(/^--trust-anchor "abc" is not sha256:<64 hex>/);
    const lone = runCli(['/nonexistent', '--distrusted-keys', `sha256:${'a'.repeat(64)}`]);
    expect(lone.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(lone.stderr).toContain('pass the pin as well');
    const date = runCli(['/nonexistent', '--trust-anchor', `sha256:${'a'.repeat(64)}`, '--distrusted-keys', `sha256:${'a'.repeat(64)}@2026-02-30T00:00:00Z`]);
    expect(date.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(date.stderr).toContain('--distrusted-keys entry');
  });

  it('exits 1 on a tampered dump and lists the failure code', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    const target = tampered.vaultEntries[1]!;
    const buf = Buffer.from(target.cose_sign1, 'base64');
    buf[buf.length - 1] = (buf[buf.length - 1]! ^ 0xff) & 0xff;
    target.cose_sign1 = buf.toString('base64');
    target.payload_hash = createHash('sha256').update(buf).digest('hex');
    writeDump(tampered);
    const result = runCli([dir]);
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain('CHAIN_SIGNATURE_INVALID');
  });

  it('--report-format=json emits a single parseable JSON object with ok:false on failure', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.orgAdminReadsCheckpoints[0]!.root_hash = 'aa'.repeat(32);
    writeDump(tampered);
    const result = runCli([dir, '--report-format=json']);
    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.ok).toBe(false);
    expect(parsed.orgAdminReads.failures.length).toBeGreaterThan(0);
  });
});

describe('runCli key-policy flags (verify#8, conformance corpus)', () => {
  const CONFORMANCE = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'conformance');
  const keySub = join(CONFORMANCE, 'export', 'key-substitution.json');
  const validExport = join(CONFORMANCE, 'export', 'valid.json');
  const oobKeys = join(CONFORMANCE, 'export', 'keys-oob.json');
  // The corpus vault key, the pin its installer printed.
  const PIN = 'sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e';

  it('an export verified against its own embedded keys is NOT ANCHORED, never PASS', () => {
    const result = runCli([keySub]);
    expect(result.exitCode).toBe(EXIT_UNANCHORED);
    expect(result.stdout).toMatch(/^\[NOT ANCHORED\]/);
    expect(result.stdout).toContain('supplied=0');
    const json = JSON.parse(runCli([keySub, '-f', 'json']).stdout) as { verdict: string; valid: boolean };
    expect(json).toMatchObject({ verdict: 'unanchored', valid: true });
  });

  it('pinned, the key-substitution fixture fails closed on the substituted key', () => {
    const result = runCli([keySub, '--trust-anchor', PIN]);
    expect(result.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    expect(result.stdout).toContain('CHAIN_SIGNING_KEY_UNANCHORED');
  });

  it('--keys + --require-supplied-keys fails the key-substitution fixture closed', () => {
    const result = runCli([keySub, '--keys', oobKeys, '--require-supplied-keys']);
    expect(result.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    expect(result.stdout).toContain('CHAIN_KEY_POLICY_VIOLATION');
    expect(result.stdout).toContain('broken at pos 2');
  });

  it('a clean export pinned on the vault key passes', () => {
    const result = runCli([validExport, '--trust-anchor', PIN]);
    expect(result.exitCode).toBe(EXIT_OK);
    expect(result.stdout).toMatch(/^\[PASS\]/);
    expect(result.stdout).toContain(`walked from ${PIN}`);
  });

  it('--require-key-id rejects a chain signed by another key', () => {
    const result = runCli([validExport, '--keys', oobKeys, '--require-key-id', 'some-other-key']);
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain('CHAIN_KEY_POLICY_VIOLATION');
  });

  it('unwraps the raw /v1/verification-keys envelope shape', () => {
    const map = JSON.parse(readFileSync(oobKeys, 'utf-8')) as Record<string, string>;
    const envelope = {
      data: Object.entries(map).map(([keyId, publicKey]) => ({ keyId, publicKey })),
      canonicalization: 'RFC8949-CDE',
    };
    const envPath = join(tmpdir(), `agledger-verify-envelope-${process.pid}.json`);
    writeFileSync(envPath, JSON.stringify(envelope));
    try {
      const result = runCli([validExport, '--keys', envPath, '--require-supplied-keys', '--trust-anchor', PIN]);
      expect(result.exitCode).toBe(EXIT_OK);
    } finally {
      rmSync(envPath, { force: true });
    }
  });

  it('rejects a malformed --keys file with a usage error, not a stack trace', () => {
    const badPath = join(tmpdir(), `agledger-verify-badkeys-${process.pid}.json`);
    writeFileSync(badPath, JSON.stringify([null]));
    try {
      const result = runCli([validExport, '--keys', badPath]);
      expect(result.exitCode).toBe(EXIT_CANNOT_VERIFY);
      expect(result.stderr).toContain('--keys file must be');
    } finally {
      rmSync(badPath, { force: true });
    }
  });

  it('rejects key-policy flags on a dump directory', () => {
    const result = runCli([CONFORMANCE, '--keys', oobKeys]);
    expect(result.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(result.stderr).toContain('/audit-export files only');
  });
});

