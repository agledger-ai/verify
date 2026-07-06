/**
 * CLI entrypoint — parsed and tested separately from main() so the unit test
 * can exercise the formatting paths without spawning a child process.
 *
 * Auto-detects the input kind from the single positional argument:
 *   - a directory  -> full-vault NDJSON dump  -> loadDump + verifyDump
 *   - a file       -> parse JSON; if it carries `exportMetadata` it is a single
 *                     `/audit-export` document -> verifyAuditExport (verify-core)
 *
 * Exit 0 on pass, nonzero on any failure or input error. Text by default;
 * `--report-format json` emits a single JSON object (not NDJSON).
 */
import { readFileSync, statSync } from 'node:fs';
import {
  verifyAuditExport,
  type OutOfBandKeyEntry,
  type RecordAuditExportInput,
  type VerifyExportResult,
} from '@agledger/verify-core';
import { loadDump } from './loader.js';
import { verifyDump } from './dump-verifier.js';
import type { VerifyReport } from './types.js';

export interface ParsedArgs {
  target: string | null;
  reportFormat: 'text' | 'json';
  showHelp: boolean;
  keys: string | null;
  requireKeyId: string | null;
  requireOutOfBandKeys: boolean;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const out: ParsedArgs = {
    target: null,
    reportFormat: 'text',
    showHelp: false,
    keys: null,
    requireKeyId: null,
    requireOutOfBandKeys: false,
  };
  const takeValue = (flag: string, next: string | undefined): string => {
    if (next === undefined || next.startsWith('-')) {
      throw new Error(`${flag} requires a value (got ${next ?? 'nothing'})`);
    }
    return next;
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg) continue;
    if (arg === '--help' || arg === '-h') {
      out.showHelp = true;
    } else if (arg === '--report-format' || arg === '-f') {
      const next = argv[i + 1];
      if (next !== 'json' && next !== 'text') {
        throw new Error(`--report-format must be "json" or "text" (got ${next ?? 'nothing'})`);
      }
      out.reportFormat = next;
      i++;
    } else if (arg.startsWith('--report-format=')) {
      const value = arg.slice('--report-format='.length);
      if (value !== 'json' && value !== 'text') {
        throw new Error(`--report-format must be "json" or "text" (got ${value})`);
      }
      out.reportFormat = value;
    } else if (arg === '--keys' || arg === '-k') {
      out.keys = takeValue('--keys', argv[i + 1]);
      i++;
    } else if (arg.startsWith('--keys=')) {
      out.keys = arg.slice('--keys='.length);
      if (!out.keys) throw new Error('--keys requires a value');
    } else if (arg === '--require-key-id') {
      out.requireKeyId = takeValue('--require-key-id', argv[i + 1]);
      i++;
    } else if (arg.startsWith('--require-key-id=')) {
      out.requireKeyId = arg.slice('--require-key-id='.length);
      if (!out.requireKeyId) throw new Error('--require-key-id requires a value');
    } else if (arg === '--require-out-of-band-keys') {
      out.requireOutOfBandKeys = true;
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown flag: ${arg}`);
    } else if (!out.target) {
      out.target = arg;
    } else {
      throw new Error(`Unexpected positional argument: ${arg}`);
    }
  }
  return out;
}

export const HELP_TEXT = `agledger-verify — offline verifier for AGLedger audit chains

Usage:
  agledger-verify <target> [--report-format text|json] [--keys <file>]
                  [--require-key-id <id>] [--require-out-of-band-keys]

<target> is auto-detected:
  - a directory: a full-vault NDJSON dump (audit_vault.ndjson + the four
    companion files) verified with the full-installation dump verifier.
  - a file: a single /audit-export JSON document (object with exportMetadata +
    entries) verified with the per-record export verifier.

Options:
  --report-format, -f         Output format. Default: text.
  --keys, -k                  Path to a JSON file holding out-of-band public
                              keys, for an /audit-export file. Accepts a
                              {keyId: SPKI-DER-base64} map, a
                              [{keyId, publicKey, ...}] list, or the raw
                              GET /v1/verification-keys response envelope
                              (the .data array is unwrapped automatically).
                              Merged over any keys embedded in the export.
  --require-key-id            Require every entry to reference this keyId.
                              Rejects otherwise-valid exports signed by a
                              retired or unexpected key.
  --require-out-of-band-keys  High-assurance: refuse keys embedded in the
                              export. Verifying an export against its own
                              embedded keys is not an independent audit;
                              supply keys via --keys instead.
  --help, -h                  Show this help.

Without --keys, an /audit-export file is verified against the signing keys
carried INSIDE that same export (the report notes this as key provenance
out-of-band=0). That proves internal consistency, not independence: an
attacker who re-signs the chain with their own embedded key still passes.
For an independent audit, fetch the keys separately (e.g. save
GET /v1/verification-keys) and pass --keys with --require-out-of-band-keys.

The key-policy flags apply to /audit-export files only; a dump directory
carries its own signed key history and rejects these flags.

A dump directory must contain:
  audit_vault.ndjson
  vault_checkpoints.ndjson
  vault_signing_keys.ndjson
  org_admin_reads.ndjson
  org_admin_reads_checkpoints.ndjson

Exits 0 on a fully verified target, nonzero on any verification failure or input error.
`;

export function formatDumpReportText(report: VerifyReport): string {
  const lines: string[] = [];
  const status = report.ok ? 'PASS' : 'FAIL';
  lines.push(`[${status}] AGLedger offline verification (dump)`);
  lines.push('');
  lines.push('audit_vault chain');
  lines.push(`  records     : ${report.vault.recordCount}`);
  lines.push(`  entries     : ${report.vault.entryCount}`);
  lines.push(`  checkpoints : ${report.vault.checkpointCount}`);
  lines.push(`  failures    : ${report.vault.failures.length}`);
  for (const f of report.vault.failures) {
    lines.push(`    [${f.code}] ${f.message}`);
  }
  lines.push('');
  lines.push('org_admin_reads chain');
  lines.push(`  orgs             : ${report.orgAdminReads.orgCount}`);
  lines.push(`  leaves           : ${report.orgAdminReads.leafCount}`);
  lines.push(`  checkpoints      : ${report.orgAdminReads.checkpointCount}`);
  lines.push(`  witness cosigned : ${report.orgAdminReads.witnessCosignedCheckpoints.length}`);
  for (const w of report.orgAdminReads.witnessCosignedCheckpoints) {
    lines.push(`    checkpoint=${w.checkpointId} witnessKeyId=${w.witnessKeyId} (signature recorded, not verified)`);
  }
  lines.push(`  failures         : ${report.orgAdminReads.failures.length}`);
  for (const f of report.orgAdminReads.failures) {
    lines.push(`    [${f.code}] ${f.message}`);
  }
  return lines.join('\n');
}

export function formatExportReportText(result: VerifyExportResult): string {
  const lines: string[] = [];
  const status = result.valid ? 'PASS' : 'FAIL';
  lines.push(`[${status}] AGLedger offline verification (audit-export)`);
  lines.push('');
  lines.push(`  record            : ${result.recordId}`);
  lines.push(`  entries           : ${result.verifiedEntries}/${result.totalEntries} verified`);
  lines.push(
    `  signature coverage: signed=${result.signatureCoverage.signed} unsigned=${result.signatureCoverage.unsigned} skipped=${result.signatureCoverage.skipped}`,
  );
  lines.push(
    `  key provenance    : out-of-band=${result.keyProvenance.outOfBand} embedded=${result.keyProvenance.embedded}`,
  );
  // verify#8: a PASS earned only against keys the export itself carries is not
  // an independent verification — a full re-sign + key-swap would also pass.
  // Say so next to the headline instead of leaving it encoded in the
  // provenance counters.
  if (result.valid && result.keyProvenance.outOfBand === 0 && result.keyProvenance.embedded > 0) {
    lines.push(
      '  WARNING           : verified only against keys embedded in the export itself. This proves internal consistency, not independence; supply --keys (and --require-out-of-band-keys) with keys obtained out of band.',
    );
  }
  if (result.brokenAt) {
    lines.push(`  broken at pos ${result.brokenAt.position}: [${result.brokenAt.code}] ${result.brokenAt.detail ?? ''}`);
  }
  // api#769: a PASS must not be read as vouching for unsigned display projections
  // (e.g. actorDisplayName). Signed attribution is the actorOwnerId/actorId UUID.
  if (result.unsignedProjectionFields.length > 0) {
    lines.push(
      `  note              : ${result.unsignedProjectionFields.length} unsigned display projection field(s) (${result.unsignedProjectionFields.join(', ')}) are NOT signature-covered — attribution is the signed actorOwnerId/actorId UUID, not these labels.`,
    );
  }
  return lines.join('\n');
}

export interface CliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

function isDirectory(target: string): boolean {
  try {
    return statSync(target).isDirectory();
  } catch {
    return false;
  }
}

function looksLikeAuditExport(value: unknown): value is RecordAuditExportInput {
  return (
    typeof value === 'object' &&
    value !== null &&
    'exportMetadata' in value &&
    'entries' in value
  );
}

export function runCli(argv: readonly string[]): CliResult {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    return { exitCode: 1, stdout: '', stderr: `${(err as Error).message}\n\n${HELP_TEXT}` };
  }
  if (parsed.showHelp) {
    return { exitCode: 0, stdout: HELP_TEXT, stderr: '' };
  }
  if (!parsed.target) {
    return { exitCode: 1, stdout: '', stderr: `Missing <target>.\n\n${HELP_TEXT}` };
  }

  const hasKeyPolicyFlags =
    parsed.keys !== null || parsed.requireKeyId !== null || parsed.requireOutOfBandKeys;

  // Directory -> full-vault dump.
  if (isDirectory(parsed.target)) {
    if (hasKeyPolicyFlags) {
      return {
        exitCode: 1,
        stdout: '',
        stderr:
          '--keys / --require-key-id / --require-out-of-band-keys apply to /audit-export files only; a dump directory carries its own signed key history (vault_signing_keys.ndjson).\n',
      };
    }
    let report: VerifyReport;
    try {
      report = verifyDump(loadDump(parsed.target));
    } catch (err) {
      return { exitCode: 1, stdout: '', stderr: `${(err as Error).message}\n` };
    }
    const stdout =
      parsed.reportFormat === 'json'
        ? JSON.stringify(report, null, 2) + '\n'
        : formatDumpReportText(report) + '\n';
    return { exitCode: report.ok ? 0 : 1, stdout, stderr: '' };
  }

  // File -> parse JSON, branch on exportMetadata.
  let raw: string;
  try {
    raw = readFileSync(parsed.target, 'utf-8');
  } catch (err) {
    return { exitCode: 1, stdout: '', stderr: `${(err as Error).message}\n` };
  }
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(raw);
  } catch (err) {
    return { exitCode: 1, stdout: '', stderr: `Invalid JSON in ${parsed.target}: ${(err as Error).message}\n` };
  }
  if (!looksLikeAuditExport(parsedJson)) {
    return {
      exitCode: 1,
      stdout: '',
      stderr: `${parsed.target} is neither a dump directory nor an /audit-export JSON document (expected exportMetadata + entries).\n\n${HELP_TEXT}`,
    };
  }

  let publicKeys: Record<string, string> | ReadonlyArray<OutOfBandKeyEntry> | undefined;
  if (parsed.keys !== null) {
    let rawKeys: string;
    try {
      rawKeys = readFileSync(parsed.keys, 'utf-8');
    } catch (err) {
      return { exitCode: 1, stdout: '', stderr: `${(err as Error).message}\n` };
    }
    let parsedKeys: unknown;
    try {
      parsedKeys = JSON.parse(rawKeys);
    } catch (err) {
      return { exitCode: 1, stdout: '', stderr: `Invalid JSON in ${parsed.keys}: ${(err as Error).message}\n` };
    }
    publicKeys = unwrapKeys(parsedKeys);
  }

  // verify-core throws TypeError at the out-of-band-key boundary when the
  // file's shape is wrong (e.g. {keyId: 42}, [null]). Surface that as a CLI
  // usage error rather than an uncaught stack trace.
  let result: VerifyExportResult;
  try {
    result = verifyAuditExport(parsedJson, {
      publicKeys,
      requireKeyId: parsed.requireKeyId ?? undefined,
      requireOutOfBandKeys: parsed.requireOutOfBandKeys,
    });
  } catch (err) {
    if (err instanceof TypeError) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: `${err.message}\nThe --keys file must be a {keyId: SPKI-DER-base64} map or a list of {keyId, publicKey, ...} entries (the .data list from /v1/verification-keys).\n`,
      };
    }
    throw err;
  }
  const stdout =
    parsed.reportFormat === 'json'
      ? JSON.stringify(result, null, 2) + '\n'
      : formatExportReportText(result) + '\n';
  return { exitCode: result.valid ? 0 : 1, stdout, stderr: '' };
}

/**
 * Accept the raw `GET /v1/verification-keys` response shape. That endpoint
 * returns an envelope `{ data: [{ keyId, publicKey, ... }], ... }`, not the
 * bare array its consumers expect — unwrap `.data` so a file saved straight
 * from the endpoint verifies without hand-editing (same behavior as
 * `agledger verify --keys`, F-732). A bare `[{keyId, publicKey}]` list or a
 * `{keyId: base64}` map passes through untouched; verify-core then validates
 * the shape and throws on anything else.
 */
function unwrapKeys(raw: unknown): Record<string, string> | ReadonlyArray<OutOfBandKeyEntry> {
  if (
    raw &&
    typeof raw === 'object' &&
    !Array.isArray(raw) &&
    Array.isArray((raw as { data?: unknown }).data)
  ) {
    return (raw as { data: ReadonlyArray<OutOfBandKeyEntry> }).data;
  }
  return raw as Record<string, string> | ReadonlyArray<OutOfBandKeyEntry>;
}
