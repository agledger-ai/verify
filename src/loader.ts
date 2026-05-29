/**
 * NDJSON dump-dir loader. Reads the five expected files and returns a typed
 * Dump. Missing files produce an explicit error rather than a silent empty
 * array — a verifier that reports OK on a half-empty dump is the wrong default.
 *
 * The loader does NOT validate row shapes beyond what's needed to walk them:
 * the verifier itself catches semantic problems. Schema-level pickiness here
 * would just duplicate what the chain checks already do.
 */
import { readFileSync } from 'node:fs';
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

function readNdjson<T>(path: string): T[] {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf-8');
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === 'ENOENT') {
      throw new Error(`Required dump file not found: ${path}`);
    }
    throw err;
  }
  const lines = raw.split('\n').filter((l) => l.trim().length > 0);
  const out: T[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    try {
      out.push(JSON.parse(line) as T);
    } catch (err) {
      throw new Error(`Invalid JSON on line ${i + 1} of ${path}: ${(err as Error).message}`);
    }
  }
  return out;
}

export function loadDump(dumpDir: string, filenames: DumpFiles = DEFAULT_FILENAMES): Dump {
  return {
    vaultEntries: readNdjson<VaultEntryDump>(join(dumpDir, filenames.vaultEntries)),
    vaultCheckpoints: readNdjson<VaultCheckpointDump>(join(dumpDir, filenames.vaultCheckpoints)),
    signingKeys: readNdjson<SigningKeyDump>(join(dumpDir, filenames.signingKeys)),
    orgAdminReads: readNdjson<OrgAdminReadDump>(join(dumpDir, filenames.orgAdminReads)),
    orgAdminReadsCheckpoints: readNdjson<OrgAdminReadsCheckpointDump>(
      join(dumpDir, filenames.orgAdminReadsCheckpoints),
    ),
  };
}
