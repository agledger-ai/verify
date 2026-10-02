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

describe('agent-signature counts on a failed run', () => {
  it('says the counts stop at the first break rather than that the chain carries none', () => {
    const failed = formatExportReportText(exportResult({ valid: false }));
    expect(failed).toContain('present=0 verified=0, counted up to the first break in each chain (none before it)');
    expect(failed).not.toContain('none on the chain');
    expect(formatExportReportText(exportResult())).toContain('present=0 verified=0 (none on the chain)');
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.vaultEntries[0]!.payload = { tampered: true };
    const report = verifyDump(tampered);
    expect(report.vault.failureCount).toBeGreaterThan(0);
    expect(formatDumpReportText(report)).toContain('counted up to the first break in each chain');
  });
});

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

  it('collects every --trust-anchor and --distrusted-key, in either form', () => {
    const a = `sha256:${'a'.repeat(64)}`;
    const b = `sha256:${'b'.repeat(64)}`;
    expect(parseArgs(['/d', '--trust-anchor', a, `--trust-anchor=${b}`, '--distrusted-key', `${b}@2026-09-01T00:00:00Z`, `--distrusted-key=${a}`])).toMatchObject({
      trustAnchors: [a, b],
      distrustedKeys: [`${b}@2026-09-01T00:00:00Z`, a],
    });
    expect(() => parseArgs(['/d', '--trust-anchor'])).toThrow(/--trust-anchor requires a value/);
  });

  it('names the renamed --distrusted-keys flag', () => {
    for (const argv of [['/d', '--distrusted-keys', 'x'], ['/d', '--distrusted-keys=x']]) {
      expect(() => parseArgs(argv)).toThrow(
        '--distrusted-keys is now --distrusted-key, given once per key: --distrusted-key sha256:<hex>[@<RFC 3339 instant>].',
      );
    }
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

  it('never renders a trusted PASS for a clean dump verified without a pin', () => {
    const { dump } = buildHappyDump();
    const text = formatDumpReportText(verifyDump(dump));
    expect(text).toMatch(/^\[VERIFIED, NOT ANCHORED\]/);
    expect(text).not.toContain('[PASS]');
    expect(text).toContain('NOT a trusted verdict');
    expect(text).toContain('Ask the operator');
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
    expect(text).toMatch(/^\[VERIFIED, NOT ANCHORED\]/);
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

  it('lists a key note under key anchoring when an honest rotation off a key distrusted after it is voided', () => {
    const fx = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'distrusted-rotation');
    const { pin, distrust } = JSON.parse(readFileSync(join(fx, 'meta.json'), 'utf-8')) as { pin: string; distrust: string };
    const result = runCli([join(fx, 'export.json'), '--keys', join(fx, 'keys.json'), '--trust-anchor', pin, '--distrusted-key', distrust]);
    expect(result.exitCode).toBe(EXIT_OK);
    expect(result.stdout).toMatch(/note: key [0-9a-f]{16}: a succession by [0-9a-f]{16}, which distrustedKeys distrusts/);
  });

  it('exits 0 on a clean dump directory pinned on its key', () => {
    const { dump, key } = buildHappyDump();
    writeDump(dump);
    const result = runCli([dir, '--trust-anchor', pinOf(key)]);
    expect(result.exitCode).toBe(EXIT_OK);
    expect(result.stdout).toMatch(/^\[PASS\]/);
  });

  it('exits 0 on a clean dump directory with no pin, and says it is not anchored', () => {
    const { dump } = buildHappyDump();
    writeDump(dump);
    const text = runCli([dir]);
    expect(text.exitCode).toBe(EXIT_OK);
    expect(text.stdout).toMatch(/^\[VERIFIED, NOT ANCHORED\]/);
    const json = runCli([dir, '-f', 'json']);
    expect(json.exitCode).toBe(EXIT_OK);
    const parsed = JSON.parse(json.stdout) as { ok: boolean; verdict: string; keyTrust: { status: string } };
    expect(parsed).toMatchObject({ ok: true, verdict: 'unanchored', keyTrust: { status: 'no_anchor' } });
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

  // The same inputs, messages and exit codes as the Python agledger-verify and
  // `agledger verify`: each is refused before the target is read.
  const PIN = `sha256:${'a'.repeat(64)}`;
  it.each([
    [['/nonexistent', '--trust-anchor', 'abc'], '--trust-anchor "abc" is not sha256:<64 hex>. Each anchor is the full SHA-256'],
    [['/nonexistent', '--trust-anchor', `${PIN},${PIN}`], `--trust-anchor "${PIN},${PIN}" is not sha256:<64 hex>.`],
    [['/nonexistent', '--trust-anchor', PIN, '--distrusted-key', `${PIN}@2026-02-30T00:00:00Z`], `--distrusted-key "${PIN}@2026-02-30T00:00:00Z" is not sha256:<64 hex>, optionally followed by @<RFC 3339 instant>`],
    [['/nonexistent', '--trust-anchor', PIN, '--distrusted-key', PIN, '--distrusted-key', PIN], `--distrusted-key names ${PIN} twice.`],
    [['/nonexistent', '--distrusted-key', PIN], '--distrusted-key acts only inside the key-statement walk, which runs from --trust-anchor; pass the pin as well.'],
    [['/nonexistent', '--trust-anchor', PIN], 'Cannot read /nonexistent: no such file or directory.'],
    [['/nonexistent', '--distrusted-keys', PIN], '--distrusted-keys is now --distrusted-key, given once per key: --distrusted-key sha256:<hex>[@<RFC 3339 instant>].'],
  ])('exits 2 on %j with the shared message', (argv, message) => {
    const text = runCli(argv);
    expect(text.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(text.stderr.startsWith(message)).toBe(true);
    const json = runCli([...argv, '-f', 'json']);
    expect(json.exitCode).toBe(EXIT_CANNOT_VERIFY);
    if (json.stdout) expect((JSON.parse(json.stdout) as { error: { message: string } }).error.message.startsWith(message)).toBe(true);
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

  it('an export verified against its own embedded keys is VERIFIED, NOT ANCHORED, never PASS', () => {
    const result = runCli([keySub]);
    expect(result.exitCode).toBe(EXIT_OK);
    expect(result.stdout).toMatch(/^\[VERIFIED, NOT ANCHORED\]/);
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

  it('a malformed export with no --keys is refused without blaming a --keys file', () => {
    const doc = JSON.parse(readFileSync(validExport, 'utf-8')) as { exportMetadata: Record<string, unknown> };
    doc.exportMetadata.signingKeyStatements = [];
    const path = join(tmpdir(), `agledger-verify-arraystatements-${process.pid}.json`);
    writeFileSync(path, JSON.stringify(doc));
    try {
      const text = runCli([path, '--trust-anchor', PIN]);
      expect(text.exitCode).toBe(EXIT_CANNOT_VERIFY);
      expect(text.stderr).toContain('signingKeyStatements must be an object keyed by key id.');
      expect(text.stderr).not.toContain('--keys');
      const json = runCli([path, '--trust-anchor', PIN, '-f', 'json']);
      expect(json.exitCode).toBe(EXIT_CANNOT_VERIFY);
      const body = JSON.parse(json.stdout) as { error: { message: string } };
      expect(body.error.message).toContain('signingKeyStatements must be an object keyed by key id.');
      expect(body.error.message).not.toContain('--keys');
      // With a good --keys file the export is still what was refused.
      expect(runCli([path, '--keys', oobKeys, '--trust-anchor', PIN]).stderr).not.toContain('--keys file must be');
    } finally {
      rmSync(path, { force: true });
    }
  });

  it('rejects key-policy flags on a dump directory', () => {
    const result = runCli([CONFORMANCE, '--keys', oobKeys]);
    expect(result.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(result.stderr).toContain('/audit-export files only');
  });
});

