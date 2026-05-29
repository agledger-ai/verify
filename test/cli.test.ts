import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_FILENAMES } from '../src/loader.js';
import { formatDumpReportText, parseArgs, runCli } from '../src/cli.js';
import { verifyDump } from '../src/dump-verifier.js';
import { buildHappyDump, cloneDump } from './fixtures.js';

describe('parseArgs', () => {
  it('captures target and defaults to text report format', () => {
    expect(parseArgs(['/tmp/dump'])).toEqual({ target: '/tmp/dump', reportFormat: 'text', showHelp: false });
  });

  it('accepts --report-format json', () => {
    expect(parseArgs(['/tmp/dump', '--report-format', 'json'])).toEqual({
      target: '/tmp/dump',
      reportFormat: 'json',
      showHelp: false,
    });
  });

  it('accepts --report-format=json', () => {
    expect(parseArgs(['/tmp/dump', '--report-format=json'])).toEqual({
      target: '/tmp/dump',
      reportFormat: 'json',
      showHelp: false,
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
});

describe('formatDumpReportText', () => {
  it('renders a PASS header for a clean dump', () => {
    const { dump } = buildHappyDump();
    const text = formatDumpReportText(verifyDump(dump));
    expect(text).toMatch(/^\[PASS\]/);
    expect(text).toContain('audit_vault chain');
    expect(text).toContain('org_admin_reads chain');
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

  it('exits 1 with a usage message when target is missing', () => {
    const result = runCli([]);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Missing <target>');
  });

  it('exits 0 on a clean dump directory', () => {
    const { dump } = buildHappyDump();
    writeDump(dump);
    const result = runCli([dir]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/^\[PASS\]/);
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
