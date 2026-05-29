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
import { verifyAuditExport, type RecordAuditExportInput, type VerifyExportResult } from '@agledger/verify-core';
import { loadDump } from './loader.js';
import { verifyDump } from './dump-verifier.js';
import type { VerifyReport } from './types.js';

export interface ParsedArgs {
  target: string | null;
  reportFormat: 'text' | 'json';
  showHelp: boolean;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const out: ParsedArgs = { target: null, reportFormat: 'text', showHelp: false };
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
  agledger-verify <target> [--report-format text|json]

<target> is auto-detected:
  - a directory: a full-vault NDJSON dump (audit_vault.ndjson + the four
    companion files) verified with the full-installation dump verifier.
  - a file: a single /audit-export JSON document (object with exportMetadata +
    entries) verified with the per-record export verifier.

Options:
  --report-format, -f   Output format. Default: text.
  --help, -h            Show this help.

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
  if (result.brokenAt) {
    lines.push(`  broken at pos ${result.brokenAt.position}: [${result.brokenAt.code}] ${result.brokenAt.detail ?? ''}`);
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

  // Directory -> full-vault dump.
  if (isDirectory(parsed.target)) {
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

  const result = verifyAuditExport(parsedJson);
  const stdout =
    parsed.reportFormat === 'json'
      ? JSON.stringify(result, null, 2) + '\n'
      : formatExportReportText(result) + '\n';
  return { exitCode: result.valid ? 0 : 1, stdout, stderr: '' };
}
