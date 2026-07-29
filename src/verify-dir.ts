/**
 * Directory-level entry point: the one place that pairs the loader's I/O with
 * the pure verification functions in `dump-verifier.ts`.
 *
 * Kept separate so `dump-verifier.ts` stays I/O-free and unit-testable against
 * in-memory fixtures.
 */
import { verifyOrgAdminReadsChains, verifyVaultChains, assembleReport } from './dump-verifier.js';
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
 * The companion files are still loaded whole: the checkpoint cross-check and
 * the org_admin_reads Merkle recomputation each need their full set, and each
 * is bounded by something far smaller than the vault.
 */
export function verifyDumpStreaming(
  dumpDir: string,
  filenames: DumpFiles = DEFAULT_FILENAMES,
): VerifyReport {
  const companions = loadCompanions(dumpDir, filenames);
  return assembleReport(
    verifyVaultChains(
      streamVaultEntries(dumpDir, filenames),
      companions.vaultCheckpoints,
      companions.signingKeys,
    ),
    verifyOrgAdminReadsChains(
      companions.orgAdminReads,
      companions.orgAdminReadsCheckpoints,
      companions.signingKeys,
    ),
  );
}
