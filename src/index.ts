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
  walkDumpKeys,
} from './dump-verifier.js';
export type { DumpKeyTrust, KeyTrustOptions, VaultChainOptions, VerifyDumpOptions } from './dump-verifier.js';
// Streams audit_vault.ndjson instead of materializing it. Prefer this over
// verifyDump(loadDump(dir)) for anything larger than a demo vault.
export { verifyDumpStreaming } from './verify-dir.js';
export type {
  Dump,
  Failure,
  FailureCode,
  KeyStatementDump,
  SigningKeyDump,
  OrgAdminReadDump,
  OrgAdminReadsCheckpointDump,
  TenantAdminReadsReport,
  VaultChainsReport,
  VaultCheckpointDump,
  VaultEntryDump,
  Verdict,
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
  EXIT_UNANCHORED,
} from './cli.js';
export type { CliResult, ParsedArgs, CannotVerifyReport, TextReportOptions } from './cli.js';

// Re-export the shared core so a caller that wants the per-record export path
// or the low-level primitives need not add a second dependency.
export {
  verifyAuditExport,
  verifyChain,
  buildKeyRegistry,
  buildAgentKeyRegistry,
  sha256Hex,
  decodeCoseSign1,
  verifyCoseSign1,
  orgReadLeafHash,
  orgReadMerkleRoot,
  verifyOrgReadInclusion,
  computeKeyTrust,
  applyKeyTrust,
  parseTrustAnchors,
  parseDistrustedKeys,
  spkiSha256,
} from '@agledger/verify-core';
export type {
  VerificationKey,
  KeyRegistry,
  NormalizedEntry,
  ChainResult,
  AgentPublicKeyJwk,
  AgentKeyRegistry,
  OptionalCheck,
  CheckApplicability,
  SuppliedKeyEntry,
  DistrustedKey,
  KeyTrust,
  KeyTrustReport,
  RecordAuditExportInput,
  VerifyExportResult,
} from '@agledger/verify-core';
