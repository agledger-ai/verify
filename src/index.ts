export { loadDump, DEFAULT_FILENAMES } from './loader.js';
export type { DumpFiles } from './loader.js';
export {
  verifyDump,
  verifyVaultChains,
  verifyOrgAdminReadsChains,
} from './dump-verifier.js';
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
} from './cli.js';
export type { CliResult, ParsedArgs } from './cli.js';

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
