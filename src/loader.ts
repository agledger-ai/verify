/**
 * NDJSON dump-dir loader. Reads the five expected files and returns a typed
 * Dump. Missing files produce an explicit error rather than a silent empty
 * array, because a verifier that reports OK on a half-empty dump is the wrong
 * default.
 *
 * The loader does NOT validate row shapes beyond what's needed to walk them:
 * the verifier itself catches semantic problems. Schema-level pickiness here
 * would just duplicate what the chain checks already do.
 *
 * **Nothing here reads a file into a single string.** Node caps a string at
 * ~512 MB (0x1fffffe8 characters) and a real vault passes that easily: 545k
 * `audit_vault` rows is a 1.18 GB NDJSON file, which used to die at read time
 * with a raw `Cannot create a string longer than 0x1fffffe8 characters`
 * (verify#14). Every file is read through `readLines`, a chunked sync reader
 * that yields one line at a time, so file size is bounded only by disk.
 *
 * `loadDump` still materializes every row, so it is bounded by heap rather than
 * by the string cap. Use `streamVaultEntries` (and `verifyDumpStreaming`, which
 * the CLI uses) when the vault is large: that path holds one chain group at a
 * time.
 */
import { closeSync, openSync, readSync } from 'node:fs';
import { StringDecoder } from 'node:string_decoder';
import { join } from 'node:path';
import type {
  Dump,
  SigningKeyDump,
  OrgAdminReadDump,
  OrgAdminReadsCheckpointDump,
  VaultCheckpointDump,
  VaultEntryDump,
} from './types.js';

export interface DumpFiles {
  /** Required. */
  vaultEntries: string;
  /** Required (may contain zero rows on a fresh install). */
  vaultCheckpoints: string;
  /** Required. */
  signingKeys: string;
  /** Required (zero rows on an org with no admin cross-party reads). */
  orgAdminReads: string;
  /** Required. */
  orgAdminReadsCheckpoints: string;
}

export const DEFAULT_FILENAMES: DumpFiles = {
  vaultEntries: 'audit_vault.ndjson',
  vaultCheckpoints: 'vault_checkpoints.ndjson',
  signingKeys: 'vault_signing_keys.ndjson',
  orgAdminReads: 'org_admin_reads.ndjson',
  orgAdminReadsCheckpoints: 'org_admin_reads_checkpoints.ndjson',
};

/**
 * Raised when a dump cannot be read or parsed at all, as opposed to a dump that
 * reads fine and fails verification. The CLI maps this to its own exit code so
 * an audit gate wired to "nonzero means the chain is broken" cannot mistake an
 * unreadable dump for a tamper alarm (verify#14).
 */
export class DumpReadError extends Error {
  override readonly name = 'DumpReadError';
}

/** Read granularity. Large enough that a 1 GB file costs ~1k syscalls, small
 *  enough that the buffer is irrelevant next to the parsed rows. */
const CHUNK_BYTES = 1 << 20;

/**
 * Yield `[line, lineNumber]` for each non-blank line of an NDJSON file, reading
 * in fixed-size chunks. Sync on purpose: keeping the whole call path synchronous
 * means `runCli` and `loadDump` keep their published signatures, so lifting the
 * size ceiling is not a breaking API change.
 *
 * `lineNumber` counts physical lines from 1, including the blank ones that are
 * skipped, so a parse error points at the line a text editor would show.
 */
export function* readLines(path: string): Generator<[string, number]> {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === 'ENOENT') {
      throw new DumpReadError(`Required dump file not found: ${path}`);
    }
    throw new DumpReadError(`Cannot read ${path}: ${(err as Error).message}`);
  }
  try {
    const buf = Buffer.allocUnsafe(CHUNK_BYTES);
    const decoder = new StringDecoder('utf8');
    let pending = '';
    let lineNumber = 0;
    for (;;) {
      const bytes = readSync(fd, buf, 0, CHUNK_BYTES, null);
      if (bytes === 0) break;
      pending += decoder.write(buf.subarray(0, bytes));
      // Walk the buffered text with an index rather than re-slicing `pending`
      // once per line: repeated prefix slicing is quadratic, and on a 1 GB file
      // that is the difference between seconds and many minutes.
      let start = 0;
      let nl = pending.indexOf('\n', start);
      while (nl !== -1) {
        const line = pending.slice(start, nl);
        start = nl + 1;
        lineNumber++;
        if (line.trim().length > 0) yield [line, lineNumber];
        nl = pending.indexOf('\n', start);
      }
      if (start > 0) pending = pending.slice(start);
    }
    pending += decoder.end();
    if (pending.trim().length > 0) {
      lineNumber++;
      yield [pending, lineNumber];
    }
  } finally {
    closeSync(fd);
  }
}

function parseLine<T>(line: string, lineNumber: number, path: string): T {
  try {
    return JSON.parse(line) as T;
  } catch (err) {
    throw new DumpReadError(
      `Invalid JSON on line ${lineNumber} of ${path}: ${(err as Error).message}`,
    );
  }
}

function readNdjson<T>(path: string): T[] {
  const out: T[] = [];
  for (const [line, lineNumber] of readLines(path)) {
    out.push(parseLine<T>(line, lineNumber, path));
  }
  return out;
}

/**
 * Stream `audit_vault.ndjson` one parsed row at a time. Nothing accumulates
 * here; the consumer decides what to hold. Paired with `verifyVaultChains`,
 * which closes each chain group as soon as the dump moves past it.
 */
export function* streamVaultEntries(
  dumpDir: string,
  filenames: DumpFiles = DEFAULT_FILENAMES,
): Generator<VaultEntryDump> {
  const path = join(dumpDir, filenames.vaultEntries);
  for (const [line, lineNumber] of readLines(path)) {
    yield parseLine<VaultEntryDump>(line, lineNumber, path);
  }
}

/**
 * Load every companion file except the vault entries. Each is bounded by
 * something small (checkpoint interval, key rotations, admin cross-party reads),
 * and the checkpoint and Merkle passes need them all in memory anyway.
 */
export function loadCompanions(
  dumpDir: string,
  filenames: DumpFiles = DEFAULT_FILENAMES,
): Omit<Dump, 'vaultEntries'> {
  return {
    vaultCheckpoints: readNdjson<VaultCheckpointDump>(join(dumpDir, filenames.vaultCheckpoints)),
    signingKeys: readNdjson<SigningKeyDump>(join(dumpDir, filenames.signingKeys)),
    orgAdminReads: readNdjson<OrgAdminReadDump>(join(dumpDir, filenames.orgAdminReads)),
    orgAdminReadsCheckpoints: readNdjson<OrgAdminReadsCheckpointDump>(
      join(dumpDir, filenames.orgAdminReadsCheckpoints),
    ),
  };
}

export function loadDump(dumpDir: string, filenames: DumpFiles = DEFAULT_FILENAMES): Dump {
  return {
    vaultEntries: readNdjson<VaultEntryDump>(join(dumpDir, filenames.vaultEntries)),
    ...loadCompanions(dumpDir, filenames),
  };
}
