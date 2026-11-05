/**
 * `agledger-verify` on an `/audit-export?evidence=true`: the inlined evidence
 * bodies are re-bound to the hashes their entries sign. The fixtures are
 * unmodified exports from a scratch Server 2.2.0 (see verify-core's
 * `fixtures/live-2.2.0`).
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { EXIT_OK, EXIT_VERIFICATION_FAILED, runCli } from '../src/cli.js';

const LIVE = fileURLToPath(new URL('./fixtures/live-2.2.0/', import.meta.url));
const exportPath = (name: string) => join(LIVE, name);
const pinOf = (path: string) => (JSON.parse(readFileSync(path, 'utf8')) as { exportMetadata: { anchoredFrom: string } }).exportMetadata.anchoredFrom;

let tmp: string | undefined;
afterEach(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
  tmp = undefined;
});

describe('inlined evidence bodies', () => {
  it('passes an unedited export and counts both bodies on the text and JSON reports', () => {
    const path = exportPath('export-evidence.json');
    const text = runCli([path, '--trust-anchor', pinOf(path)]);
    expect(text.exitCode).toBe(EXIT_OK);
    expect(text.stdout).toContain('evidence bodies   : present=2 verified=2 failed=0 (2 hashed (RFC 8785, SHA-256) to the evidenceHash or payloadHash its entry signs)');
    const json = JSON.parse(runCli([path, '--trust-anchor', pinOf(path), '-f', 'json']).stdout) as { evidenceBinding: unknown };
    expect(json.evidenceBinding).toEqual({ present: 2, verified: 2, clientHashed: 0, failed: 0 });
  });

  it('fails an export whose dispute evidence body was edited (exit 1)', () => {
    const path = exportPath('export-evidence.json');
    const exp = JSON.parse(readFileSync(path, 'utf8')) as { entries: Array<{ entryType: string; evidence?: Record<string, unknown> }> };
    const entry = exp.entries.find((e) => e.entryType === 'DISPUTE_EVIDENCE')!;
    entry.evidence = { ...entry.evidence, doc: 'invoice-999' };
    tmp = mkdtempSync(join(tmpdir(), 'agl-evidence-'));
    const edited = join(tmp, 'edited.json');
    writeFileSync(edited, JSON.stringify(exp));
    const r = runCli([edited, '--trust-anchor', pinOf(path)]);
    expect(r.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    expect(r.stdout).toContain('CHAIN_EVIDENCE_BINDING_MISMATCH');
    expect(r.stdout).toContain('evidence bodies   : present=2 verified=1 failed=1');
  });

  it('reports an encrypted-mode completion as client-hashed, not re-bound', () => {
    const path = exportPath('export-encrypted-evidence.json');
    const r = runCli([path, '--trust-anchor', pinOf(path)]);
    expect(r.exitCode).toBe(EXIT_OK);
    expect(r.stdout).toContain('client-hashed=1');
    expect(r.stdout).toContain('so it was NOT re-bound');
  });

  it('says so when an export carries no bodies at all', () => {
    const path = exportPath('export-evidence.json');
    const exp = JSON.parse(readFileSync(path, 'utf8')) as { entries: Array<{ evidence?: unknown }> };
    for (const e of exp.entries) delete e.evidence;
    tmp = mkdtempSync(join(tmpdir(), 'agl-evidence-'));
    const bare = join(tmp, 'bare.json');
    writeFileSync(bare, JSON.stringify(exp));
    expect(runCli([bare, '--trust-anchor', pinOf(path)]).stdout).toContain('(none inlined: the export was taken without ?evidence=true, so it carries hashes only)');
  });
});
