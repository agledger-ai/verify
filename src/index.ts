export {
  loadDump,
  loadCompanions,
  streamVaultEntries,
  readLines,
  DumpReadError,
  DEFAULT_FILENAMES,
} from './loader.js';
export type { DumpFiles } from './loader.js';
export {
  verifyDump,
  verifyVaultChains,
  verifyOrgAdminReadsChains,
  assembleReport,
} from './dump-verifier.js';
// Streams audit_vault.ndjson instead of materializing it. Prefer this over
// verifyDump(loadDump(dir)) for anything larger than a demo vault.
export { verifyDumpStreaming } from './verify-dir.js';
export type {
  Dump,
  Failure,
  FailureCode,
  SigningKeyDump,
  OrgAdminReadDump,
  OrgAdminReadsCheckpointDump,
  TenantAdminReadsReport,
  VaultChainsReport,
  VaultCheckpointDump,
  VaultEntryDump,
  VerifyReport,
} from './types.js';
export {
  parseArgs,
  runCli,
  formatDumpReportText,
  formatExportReportText,
  HELP_TEXT,
  EXIT_OK,
  EXIT_VERIFICATION_FAILED,
  EXIT_CANNOT_VERIFY,
} from './cli.js';
export type { CliResult, ParsedArgs, CannotVerifyReport } from './cli.js';

// Re-export the shared core so a caller that wants the per-record export path
// or the low-level primitives need not add a second dependency.
export {
  verifyAuditExport,
  verifyChain,
  buildKeyRegistry,
  sha256Hex,
  decodeCoseSign1,
  verifyCoseSign1,
  merkleRoot,
  verifyInclusion,
} from '@agledger/verify-core';
export type {
  VerificationKey,
  KeyRegistry,
  NormalizedEntry,
  ChainResult,
  OutOfBandKeyEntry,
  RecordAuditExportInput,
  VerifyExportResult,
} from '@agledger/verify-core';
