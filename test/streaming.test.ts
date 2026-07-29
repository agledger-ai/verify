/**
 * Streaming dump verification (verify#14).
 *
 * The bug this covers: `audit_vault.ndjson` used to be read into one string, so
 * any vault past Node's ~512 MB string cap died with a raw
 * `Cannot create a string longer than 0x1fffffe8 characters` before a single
 * row was checked. A real quarter of operation for one mid-size org produced a
 * 1.18 GB file, so the tool failed exactly where an audit needs it.
 *
 * The size case itself needs ~1 GB of disk and is opt-in via
 * AGLEDGER_VERIFY_LARGE_FILE_TEST=1. Everything else here is cheap and always
 * runs: chunk-boundary handling, equivalence with the in-memory path on the
 * conformance corpus, the fail-closed guard on a re-ordered dump, and the exit
 * code split that stops an unreadable dump from reading as a tamper alarm.
 */
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_FILENAMES,
  DumpReadError,
  loadDump,
  readLines,
  streamVaultEntries,
} from '../src/loader.js';
import { MAX_REPORTED_FAILURES, verifyDump } from '../src/dump-verifier.js';
import { verifyDumpStreaming } from '../src/verify-dir.js';
import {
  EXIT_CANNOT_VERIFY,
  EXIT_OK,
  EXIT_VERIFICATION_FAILED,
  formatDumpReportText,
  runCli,
  type CannotVerifyReport,
} from '../src/cli.js';

const here = dirname(fileURLToPath(import.meta.url));
const CORPUS_DUMPS = join(here, '..', 'testdata', 'conformance', 'dump');
const VALID_DUMP = join(CORPUS_DUMPS, 'valid');

/** Every dump vector in the conformance corpus, valid and tampered alike. */
const VECTORS = [
  'valid',
  'chain-empty',
  'chain-key-expired',
  'chain-oidc-actor-mismatch',
  'chain-payload-binding-mismatch',
  'checkpoint-hash-mismatch',
  'checkpoint-row-missing',
  'tenant-checkpoint-fork',
  'tenant-checkpoint-root-mismatch',
];

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'agledger-verify-stream-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Copy a corpus dump into the temp dir, optionally rewriting one file. */
function stageDump(source: string, overrides: Partial<Record<string, string>> = {}): string {
  for (const filename of Object.values(DEFAULT_FILENAMES)) {
    const override = overrides[filename];
    writeFileSync(
      join(dir, filename),
      override ?? readFileSync(join(source, filename), 'utf8'),
    );
  }
  return dir;
}

describe('readLines chunk handling', () => {
  it('reassembles lines that span a read-chunk boundary', () => {
    // The reader works in 1 MiB chunks, so lines must be reassembled across
    // them. Rows here are ~4 KB, which puts hundreds of boundaries in play.
    const path = join(dir, 'big.ndjson');
    const rowCount = 800;
    const rows = Array.from({ length: rowCount }, (_, i) =>
      JSON.stringify({ i, filler: 'x'.repeat(4000) }),
    );
    writeFileSync(path, rows.join('\n') + '\n');
    expect(statSync(path).size).toBeGreaterThan(1 << 20);

    const seen = [...readLines(path)];
    expect(seen).toHaveLength(rowCount);
    // Content survives intact, and the line numbers are physical file lines.
    expect(seen[0]![1]).toBe(1);
    expect(seen[rowCount - 1]![1]).toBe(rowCount);
    for (const [line, n] of seen) {
      expect((JSON.parse(line) as { i: number }).i).toBe(n - 1);
    }
  });

  it('does not split a multi-byte character across chunks', () => {
    // A 3-byte character straddling a chunk boundary would decode to U+FFFD if
    // each chunk were decoded independently.
    const path = join(dir, 'utf8.ndjson');
    const pad = 'a'.repeat((1 << 20) - 3);
    writeFileSync(path, `{"pad":"${pad}","s":"日本語テキスト"}\n`);
    const [entry] = [...readLines(path)];
    const parsed = JSON.parse(entry![0]) as { s: string };
    expect(parsed.s).toBe('日本語テキスト');
  });

  it('reports the physical line number on malformed JSON, blank lines included', () => {
    const path = join(dir, DEFAULT_FILENAMES.vaultEntries);
    for (const name of Object.values(DEFAULT_FILENAMES)) writeFileSync(join(dir, name), '');
    writeFileSync(path, '{"id":"a"}\n\n\n{not json\n');
    expect(() => loadDump(dir)).toThrow(/Invalid JSON on line 4/);
  });

  it('raises DumpReadError, not a bare Error, when a file is missing', () => {
    expect(() => loadDump(dir)).toThrow(DumpReadError);
  });
});

describe('streaming verification matches the in-memory path', () => {
  it.each(VECTORS)('produces an identical report for the %s vector', (vector) => {
    const source = join(CORPUS_DUMPS, vector);
    const streamed = verifyDumpStreaming(source);
    const inMemory = verifyDump(loadDump(source));

    expect(streamed.ok).toBe(inMemory.ok);
    expect(streamed.vault.recordCount).toBe(inMemory.vault.recordCount);
    expect(streamed.vault.entryCount).toBe(inMemory.vault.entryCount);
    expect(streamed.vault.checkpointCount).toBe(inMemory.vault.checkpointCount);
    // Failure ORDER differs by construction (streaming closes each chain's
    // checkpoints with the chain), so compare as sets of code+scope.
    const key = (f: { code: string; scopeId?: string; position?: number }): string =>
      `${f.code}|${f.scopeId ?? ''}|${f.position ?? ''}`;
    expect(new Set(streamed.vault.failures.map(key))).toEqual(
      new Set(inMemory.vault.failures.map(key)),
    );
    expect(new Set(streamed.orgAdminReads.failures.map(key))).toEqual(
      new Set(inMemory.orgAdminReads.failures.map(key)),
    );
  });

  it('holds one chain group at a time rather than the whole vault', () => {
    // The generator is the memory contract: pulling one row must not force the
    // rest of the file to be parsed.
    const iterator = streamVaultEntries(VALID_DUMP);
    const first = iterator.next();
    expect(first.done).toBe(false);
    expect(first.value.chain_position).toBe(1);
    iterator.return?.(undefined as never);
  });
});

describe('fail-closed on a dump that is not in producer order', () => {
  it('refuses when a chain reappears after its group was closed', () => {
    // The dump tool emits ORDER BY record_id, chain_position, so a chain's rows
    // are contiguous. Interleave them and the streaming walk would otherwise
    // verify a partial chain and report clean, which is the one way a
    // streaming verifier can be less safe than the buffered one.
    const rows = readFileSync(join(VALID_DUMP, DEFAULT_FILENAMES.vaultEntries), 'utf8')
      .split('\n')
      .filter((l) => l.trim().length > 0);
    // rows 0..2 are one chain; move a later chain's row into the middle of it.
    const reordered = [rows[0]!, rows[1]!, rows[3]!, rows[2]!, rows[4]!];
    const staged = stageDump(VALID_DUMP, {
      [DEFAULT_FILENAMES.vaultEntries]: reordered.join('\n') + '\n',
    });

    const report = verifyDumpStreaming(staged);
    expect(report.ok).toBe(false);
    // The truncated first chain also trips its own checkpoint, so the order
    // violation is not necessarily the first failure. What matters is that it
    // is reported and the dump does not pass.
    expect(
      report.vault.failures.some(
        (f) => f.code === 'UNSUPPORTED_FORMAT' && /not in producer order/.test(f.message),
      ),
    ).toBe(true);
  });

  it('still verifies the same dump clean when the rows are in producer order', () => {
    expect(verifyDumpStreaming(stageDump(VALID_DUMP)).ok).toBe(true);
  });
});

describe('exit codes separate "failed" from "could not verify"', () => {
  it('exits 0 on the valid corpus dump', () => {
    expect(runCli([VALID_DUMP]).exitCode).toBe(EXIT_OK);
  });

  it('exits 1 when a dump reads fine and the chain does not hold up', () => {
    expect(runCli([join(CORPUS_DUMPS, 'chain-payload-binding-mismatch')]).exitCode).toBe(
      EXIT_VERIFICATION_FAILED,
    );
  });

  it('exits 2 when a required dump file is missing', () => {
    const result = runCli([dir]);
    expect(result.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(result.stderr).toMatch(/Required dump file not found/);
  });

  it('exits 2 on malformed NDJSON rather than reporting a broken chain', () => {
    // Keep a well-formed first row so the walk actually reaches the bad line:
    // a streaming reader only meets a parse error when it gets there.
    const firstRow = readFileSync(join(VALID_DUMP, DEFAULT_FILENAMES.vaultEntries), 'utf8')
      .split('\n')[0]!;
    const staged = stageDump(VALID_DUMP, {
      [DEFAULT_FILENAMES.vaultEntries]: `${firstRow}\n{ this is not json\n`,
    });
    const result = runCli([staged]);
    expect(result.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(result.stderr).toMatch(/Invalid JSON on line 2/);
  });

  it('emits parseable JSON for an input error under --report-format json', () => {
    // A machine consumer asked for JSON; handing it a bare line of prose is how
    // an unreadable dump gets logged as a tamper alarm.
    const result = runCli([dir, '--report-format', 'json']);
    expect(result.exitCode).toBe(EXIT_CANNOT_VERIFY);
    const parsed = JSON.parse(result.stdout) as CannotVerifyReport;
    expect(parsed.ok).toBe(false);
    expect(parsed.error.kind).toBe('input');
    expect(parsed.error.message).toMatch(/Required dump file not found/);
  });
});

describe('failure reporting is bounded', () => {
  it('caps the failure list, keeps the true count, and says what was withheld', () => {
    // A systemic problem on a large vault yields one failure per entry. Repeat
    // a single valid row so every position collides: enough failures to cross
    // the cap without needing a large file.
    const row = readFileSync(join(VALID_DUMP, DEFAULT_FILENAMES.vaultEntries), 'utf8')
      .split('\n')[0]!;
    const rowCount = MAX_REPORTED_FAILURES + 250;
    const staged = stageDump(VALID_DUMP, {
      [DEFAULT_FILENAMES.vaultEntries]: `${row}\n`.repeat(rowCount),
    });

    const report = verifyDumpStreaming(staged);
    expect(report.ok).toBe(false);
    expect(report.vault.failureCount).toBeGreaterThan(MAX_REPORTED_FAILURES);
    expect(report.vault.failures).toHaveLength(MAX_REPORTED_FAILURES);

    const text = formatDumpReportText(report);
    expect(text).toContain(`failures    : ${report.vault.failureCount}`);
    expect(text).toMatch(/\.\.\. and \d+ more not shown/);
    // The whole point: the report stays small enough to read.
    expect(text.length).toBeLessThan(1_000_000);
  });
});

describe('vaults past the Node string cap', () => {
  const enabled = process.env.AGLEDGER_VERIFY_LARGE_FILE_TEST === '1';
  const MAX_STRING = 0x1fffffe8;

  it.skipIf(!enabled)('reads an audit_vault.ndjson larger than 512 MB', () => {
    const path = join(dir, DEFAULT_FILENAMES.vaultEntries);
    const row = JSON.stringify({ id: 'x', filler: 'y'.repeat(2000) }) + '\n';
    const block = row.repeat(500);
    const target = MAX_STRING + (64 << 20);
    const handle: string[] = [];
    let written = 0;
    while (written < target) {
      handle.push(block);
      written += block.length;
    }
    // Write in appends so the test itself never builds an oversized string.
    writeFileSync(path, '');
    for (const chunk of handle) writeFileSync(path, chunk, { flag: 'a' });
    expect(statSync(path).size).toBeGreaterThan(MAX_STRING);

    let count = 0;
    for (const _line of readLines(path)) count++;
    expect(count).toBe(handle.length * 500);
  }, 600_000);
});
