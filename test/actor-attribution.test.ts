/**
 * Actor attribution on the full-dump path.
 *
 * `actor_key_id` / `actor_role` / `actor_owner_id` are the columns a report
 * displays as "who did this", and they are signature-covered in the COSE
 * protected header (CWT_Claims label 15 -> private label -65539). Before this
 * check a dump row could be re-attributed to another actor and the vault
 * would still verify clean, which made the attribution the export guide points
 * an auditor at unverifiable.
 *
 * The dump under `fixtures/live-2.0.0/dump` is unmodified API 2.0.0 output,
 * copied per test so it can be tampered with, and every run is pinned on that
 * instance's key.
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EXIT_OK, EXIT_VERIFICATION_FAILED, runCli as runCliUnpinned } from '../src/cli.js';
import type { VaultEntryDump, VerifyReport } from '../src/types.js';
import { LIVE_DIR, LIVE_PIN } from './fixtures.js';

const runCli = (argv: readonly string[]) => runCliUnpinned([...argv, '--trust-anchor', LIVE_PIN]);

const LIVE_DUMP = join(LIVE_DIR, 'dump');
const LIVE_EXPORT = join(LIVE_DIR, 'export-cert-lifecycle.json');

function liveDumpCopy(): string {
  const copy = mkdtempSync(join(tmpdir(), 'agledger-verify-actor-'));
  cpSync(LIVE_DUMP, copy, { recursive: true });
  return copy;
}

let dir: string;
beforeEach(() => {
  dir = liveDumpCopy();
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function vaultRows(): VaultEntryDump[] {
  return readFileSync(join(dir, 'audit_vault.ndjson'), 'utf-8')
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as VaultEntryDump);
}

function writeVault(rows: VaultEntryDump[]): void {
  writeFileSync(join(dir, 'audit_vault.ndjson'), rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
}

describe('actor attribution on a full vault dump', () => {
  it('verifies clean and reports the check as applied', () => {
    const r = runCli([dir, '-f', 'json']);
    expect(r.exitCode).toBe(EXIT_OK);
    const report = JSON.parse(r.stdout) as VerifyReport;
    expect(report.ok).toBe(true);
    expect(report.vault.optionalChecks.actor_attribution).toBe('applied');
  });

  it('refuses a row re-attributed to another owner', () => {
    const rows = vaultRows();
    const target = rows[0]!;
    const original = target.actor_owner_id;
    target.actor_owner_id = '00000000-0000-7000-8000-000000000000';
    expect(target.actor_owner_id).not.toBe(original);
    writeVault(rows);

    const r = runCli([dir, '-f', 'json']);
    expect(r.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    const report = JSON.parse(r.stdout) as VerifyReport;
    expect(report.ok).toBe(false);
    const codes = report.vault.failures.map((f) => f.code);
    expect(codes).toContain('CHAIN_ACTOR_ATTRIBUTION_MISMATCH');
  });

  it('refuses a rewritten actor key id and a rewritten role', () => {
    for (const [field, value] of [
      ['actor_key_id', '00000000-0000-7000-8000-000000000001'],
      ['actor_role', 'platform'],
    ] as const) {
      rmSync(dir, { recursive: true, force: true });
      dir = liveDumpCopy();
      const rows = vaultRows();
      rows[0]![field] = value;
      writeVault(rows);

      const r = runCli([dir, '-f', 'json']);
      expect(r.exitCode).toBe(EXIT_VERIFICATION_FAILED);
      const report = JSON.parse(r.stdout) as VerifyReport;
      expect(report.vault.failures.map((f) => f.code)).toContain('CHAIN_ACTOR_ATTRIBUTION_MISMATCH');
    }
  });
});

describe('the text note says whether attribution was checked, never that it agreed when it did not', () => {
  it('claims agreement only on a run that verified', () => {
    const doc = JSON.parse(readFileSync(LIVE_EXPORT, 'utf-8')) as { entries: { actorOwnerId: string }[] };
    const exportPath = join(dir, 'export.json');

    writeFileSync(exportPath, JSON.stringify(doc));
    const clean = runCli([exportPath]);
    expect(clean.exitCode).toBe(EXIT_OK);
    expect(clean.stdout).toContain('was cross-checked against the signed actor claim and agrees');

    // `applied` means the check RAN. A failed run must not be told it agreed.
    doc.entries[0]!.actorOwnerId = '00000000-0000-7000-8000-000000000000';
    writeFileSync(exportPath, JSON.stringify(doc));
    const tampered = runCli([exportPath]);
    expect(tampered.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    expect(tampered.stdout).toContain('CHAIN_ACTOR_ATTRIBUTION_MISMATCH');
    expect(tampered.stdout).not.toContain('and agrees');
    expect(tampered.stdout).toContain('this run did not verify');
  });
});
