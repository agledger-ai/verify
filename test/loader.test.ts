import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_FILENAMES, loadDump } from '../src/loader.js';

describe('loadDump', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'agledger-verify-loader-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writeAll(rows: Record<keyof typeof DEFAULT_FILENAMES, unknown[]>): void {
    for (const [key, filename] of Object.entries(DEFAULT_FILENAMES) as Array<
      [keyof typeof DEFAULT_FILENAMES, string]
    >) {
      const lines = rows[key].map((r) => JSON.stringify(r)).join('\n');
      writeFileSync(join(dir, filename), lines + (lines ? '\n' : ''));
    }
  }

  it('reads NDJSON files into typed arrays', () => {
    writeAll({
      vaultEntries: [{ id: 'a', record_id: 'm', chain_position: 1 }],
      vaultCheckpoints: [],
      signingKeys: [{ key_id: 'k', public_key: 'pk' }],
      orgAdminReads: [],
      orgAdminReadsCheckpoints: [],
    });
    const dump = loadDump(dir);
    expect(dump.vaultEntries).toHaveLength(1);
    expect(dump.signingKeys).toHaveLength(1);
    expect(dump.orgAdminReads).toHaveLength(0);
  });

  it('skips blank lines without inserting empty rows', () => {
    writeFileSync(join(dir, DEFAULT_FILENAMES.vaultEntries), '{"id":"a"}\n\n{"id":"b"}\n');
    writeFileSync(join(dir, DEFAULT_FILENAMES.vaultCheckpoints), '');
    writeFileSync(join(dir, DEFAULT_FILENAMES.signingKeys), '');
    writeFileSync(join(dir, DEFAULT_FILENAMES.orgAdminReads), '');
    writeFileSync(join(dir, DEFAULT_FILENAMES.orgAdminReadsCheckpoints), '');
    const dump = loadDump(dir);
    expect(dump.vaultEntries.map((e) => e.id)).toEqual(['a', 'b']);
  });

  it('throws when a required file is missing', () => {
    expect(() => loadDump(dir)).toThrow(/Required dump file not found/);
  });

  it('reports the line number on malformed JSON', () => {
    writeFileSync(join(dir, DEFAULT_FILENAMES.vaultEntries), '{"id":"a"}\n{not json\n');
    writeFileSync(join(dir, DEFAULT_FILENAMES.vaultCheckpoints), '');
    writeFileSync(join(dir, DEFAULT_FILENAMES.signingKeys), '');
    writeFileSync(join(dir, DEFAULT_FILENAMES.orgAdminReads), '');
    writeFileSync(join(dir, DEFAULT_FILENAMES.orgAdminReadsCheckpoints), '');
    expect(() => loadDump(dir)).toThrow(/Invalid JSON on line 2/);
  });
});
