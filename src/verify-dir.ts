/**
 * Directory-level entry point: the one place that pairs the loader's I/O with
 * the pure verification functions in `dump-verifier.ts`.
 *
 * Kept separate so `dump-verifier.ts` stays I/O-free and unit-testable against
 * in-memory fixtures.
 */
import {
  verifyOrgAdminReadsChains,
  verifyVaultChains,
  assembleReport,
  walkDumpKeys,
  type VerifyDumpOptions,
} from './dump-verifier.js';
import { DEFAULT_FILENAMES, loadCompanions, streamVaultEntries, type DumpFiles } from './loader.js';
import type { VerifyReport } from './types.js';

/**
 * Verify a dump directory without ever holding the whole vault in memory.
 *
 * Produces the same report as `verifyDump(loadDump(dir))`, but streams
 * `audit_vault.ndjson`, so the ceiling is disk rather than Node's ~512 MB
 * string cap and the heap a fully materialized vault would need (verify#14).
 * Peak memory is one chain group. This is the path the CLI takes.
 *
 * The companion files are still loaded whole: the checkpoint cross-check,
 * the org_admin_reads Merkle recomputation and the key-statement walk each
 * need their full set, and each is bounded by something far smaller than the
 * vault.
 *
 * `options.trustAnchors` (with `options.distrustedKeys`) runs the key walk,
 * and `options.agentKeys` enables the offline agent-signature check (see
 * `VerifyDumpOptions`). Throws `TypeError` on a malformed anchor or
 * distrusted key, and `DumpReadError` on a file that cannot be read.
 */
export function verifyDumpStreaming(
  dumpDir: string,
  filenames: DumpFiles = DEFAULT_FILENAMES,
  options: VerifyDumpOptions = {},
): VerifyReport {
  const companions = loadCompanions(dumpDir, filenames);
  const keys = walkDumpKeys(companions.signingKeys, companions.keyStatements, options);
  return assembleReport(
    verifyVaultChains(streamVaultEntries(dumpDir, filenames), companions.vaultCheckpoints, keys, options),
    verifyOrgAdminReadsChains(companions.orgAdminReads, companions.orgAdminReadsCheckpoints, keys),
    keys,
  );
}
