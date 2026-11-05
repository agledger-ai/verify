/**
 * CLI entrypoint, parsed and tested separately from main() so the unit test
 * can exercise the formatting paths without spawning a child process.
 *
 * Auto-detects the input kind from the single positional argument:
 *   - a directory  -> full-vault NDJSON dump  -> loadDump + verifyDump
 *   - a file       -> parse JSON; if it carries `exportMetadata` it is a single
 *                     `/audit-export` document -> verifyAuditExport (verify-core)
 *
 * Exit codes distinguish the two ways this can end badly, because they mean
 * opposite things to an audit gate:
 *
 *   0  verified, no failures (trusted with a --trust-anchor, flagged
 *      as not anchored without one)
 *   1  VERIFICATION FAILED, the chain or log does not hold up
 *   2  COULD NOT VERIFY, the input could not be read or parsed at all
 *
 * Collapsing those into a single nonzero code is what made an oversized vault
 * look like a tamper alarm. A gate wired to "nonzero means the chain is broken"
 * must be able to tell "the evidence is bad" from "I never saw the evidence".
 *
 * Text by default; `--report-format json` emits a single JSON object (not
 * NDJSON), including for input errors, so a machine consumer always gets
 * parseable output.
 */
import { existsSync, readFileSync, statSync } from 'node:fs';
import {
  buildAgentKeyRegistry,
  assertNotPinnedAndDistrusted,
  parseDistrustedKeys,
  parseTrustAnchors,
  verifyAuditExport,
  normalizeFederationKey,
  type AccountedEntry,
  type AgentPublicKeyJwk,
  type CheckApplicability,
  type DistrustedKey,
  type KeyTrustReport,
  type RecordAuditExportInput,
  type SuppliedKeyEntry,
  type VerifyExportResult,
} from '@agledger/verify-core';
import { DumpReadError } from './loader.js';
import { verifyDumpStreaming } from './verify-dir.js';
import type { Failure, Verdict, VerifyReport } from './types.js';

/** Verified, no failures. The report's verdict says whether keys were anchored. */
export const EXIT_OK = 0;
/** The target was read and verified, and it does not hold up. */
export const EXIT_VERIFICATION_FAILED = 1;
/** The target could not be read, parsed, or addressed at all. No verdict was
 *  reached, which is NOT the same as a failed verdict. */
export const EXIT_CANNOT_VERIFY = 2;

const EXIT_BY_VERDICT: Readonly<Record<Verdict, number>> = {
  trusted: EXIT_OK,
  unanchored: EXIT_OK,
  failed: EXIT_VERIFICATION_FAILED,
};

/** Machine-readable shape emitted under `--report-format json` when no verdict
 *  could be reached. Distinguishable from a VerifyReport by the `error` key. */
export interface CannotVerifyReport {
  ok: false;
  error: { kind: 'input'; message: string };
}

export interface ParsedArgs {
  target: string | null;
  reportFormat: 'text' | 'json';
  showHelp: boolean;
  showVersion: boolean;
  keys: string | null;
  requireKeyId: string | null;
  requireSuppliedKeys: boolean;
  agentKeys: string | null;
  /** `--trust-anchor` values, in the order given. */
  trustAnchors: string[];
  /** `--distrusted-key` values, one entry each, in the order given. */
  distrustedKeys: string[];
  /** `--federation-key` values, `<hubId>=<base64 key>` each, in the order given. */
  federationKeys: string[];
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const out: ParsedArgs = {
    target: null,
    reportFormat: 'text',
    showHelp: false,
    showVersion: false,
    keys: null,
    requireKeyId: null,
    requireSuppliedKeys: false,
    agentKeys: null,
    trustAnchors: [],
    distrustedKeys: [],
    federationKeys: [],
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
    } else if (arg === '--version' || arg === '-V') {
      out.showVersion = true;
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
    } else if (arg === '--agent-keys') {
      out.agentKeys = takeValue('--agent-keys', argv[i + 1]);
      i++;
    } else if (arg.startsWith('--agent-keys=')) {
      out.agentKeys = arg.slice('--agent-keys='.length);
      if (!out.agentKeys) throw new Error('--agent-keys requires a value');
    } else if (arg === '--trust-anchor') {
      out.trustAnchors.push(takeValue('--trust-anchor', argv[i + 1]));
      i++;
    } else if (arg.startsWith('--trust-anchor=')) {
      const value = arg.slice('--trust-anchor='.length);
      if (!value) throw new Error('--trust-anchor requires a value');
      out.trustAnchors.push(value);
    } else if (arg === '--distrusted-key') {
      out.distrustedKeys.push(takeValue('--distrusted-key', argv[i + 1]));
      i++;
    } else if (arg.startsWith('--distrusted-key=')) {
      const value = arg.slice('--distrusted-key='.length);
      if (!value) throw new Error('--distrusted-key requires a value');
      out.distrustedKeys.push(value);
    } else if (arg === '--federation-key') {
      out.federationKeys.push(takeValue('--federation-key', argv[i + 1]));
      i++;
    } else if (arg.startsWith('--federation-key=')) {
      const value = arg.slice('--federation-key='.length);
      if (!value) throw new Error('--federation-key requires a value');
      out.federationKeys.push(value);
    } else if (arg === '--distrusted-keys' || arg.startsWith('--distrusted-keys=')) {
      throw new Error(PLURAL_DISTRUSTED);
    } else if (arg === '--require-supplied-keys') {
      out.requireSuppliedKeys = true;
    } else if (arg === '--require-out-of-band-keys') {
      throw new Error('--require-out-of-band-keys is now --require-supplied-keys: a key fetched from the Server is supplied, not independent of it. Pin --trust-anchor for that.');
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

const PLURAL_DISTRUSTED =
  '--distrusted-keys is now --distrusted-key, given once per key: --distrusted-key sha256:<hex>[@<RFC 3339 instant>].';

export const HELP_TEXT = `agledger-verify: offline verifier for AGLedger audit chains

Usage:
  agledger-verify <target> [--trust-anchor sha256:<hex>]...
                  [--distrusted-key sha256:<hex>[@<instant>]]...
                  [--agent-keys <file>]
                  [--federation-key <hubId>=<key>]...
                  [--report-format text|json]
                  [--keys <file>] [--require-key-id <id>]
                  [--require-supplied-keys]

<target> is auto-detected:
  - a directory: a full-vault NDJSON dump (audit_vault.ndjson + the five
    companion files) verified with the full-installation dump verifier.
  - a file: a single /audit-export JSON document (object with exportMetadata +
    entries) verified with the per-record export verifier.

Options:
  --trust-anchor              SPKI digest of a vault key you hold or took out
                              of band, as sha256:<64 hex>. Repeatable. The
                              installer prints the first key's digest, and the
                              Server's signing-key-digest.js derives one from
                              any key. The signed key statements are walked
                              from the pins, and an entry, checkpoint or
                              read-log row signed by a key they do not reach
                              fails (CHAIN_SIGNING_KEY_UNANCHORED and its
                              checkpoint and read-log counterparts). Applies
                              to a dump directory and to an /audit-export file.
  --distrusted-key            A key the operator distrusts, as in the Server's
                              VAULT_DISTRUSTED_KEYS: sha256:<64 hex>,
                              optionally @<RFC 3339 instant>. Repeat it once
                              per key. What such a key stored from the
                              instant on (or, with none, from its retirement)
                              counts for nothing in the walk. Requires
                              --trust-anchor. A dated entry may name a pinned
                              key: the pin then vouches for what the key
                              stored before the instant. On a dump, entries
                              it signed before a trusted key retired it are
                              listed as accounted for and do not fail. Where
                              an export lists a key retired at the instant the
                              Server distrusts it from (distrustedFrom),
                              earlier than its signed retirement, a run without
                              the same entry fails on that window, and the
                              finding names the --distrusted-key to confirm
                              with the Server's operator.
  --report-format, -f         Output format. Default: text.
  --federation-key            <hubId>=<key>: a peer Server's federation key,
                              as its operator gives it (base64 SPKI DER, or
                              base64 of the raw 32 bytes, the form the
                              handshake registered). Repeat it once per peer.
                              A receiving Server seals each peer message it
                              accepts on the chain entry it writes
                              (payload.wire), as the peer signed it. Every
                              sealed message is held to its body hash and to
                              its entry; one from a hub given here also has
                              its signature re-verified under that key, which
                              proves what the peer asserted from this
                              Server's export alone. A failure is
                              CHAIN_FEDERATION_WIRE_INVALID. Applies to a dump
                              directory and to an /audit-export file.
  --agent-keys                Path to a JSON file holding the Ed25519 public
                              keys of agent certs: a JWK, a list of JWKs, or a
                              {keys:[...]} JWK Set. An entry may wrap its key
                              as {publicKeyJwk:{...}}. Each is the
                              publicKeyJwk an agent sent at cert exchange (also
                              the cnf.jwk claim in its certJws). An entry whose
                              sealed agent signature names one of them by
                              thumbprint has that signature re-verified
                              offline, and fails CHAIN_AGENT_SIGNATURE_INVALID
                              if it does not verify. Applies to a dump
                              directory (added to the cert keys the dump
                              itself signs) and to an /audit-export file.
  --keys, -k                  Path to a JSON file holding supplied public
                              keys, for an /audit-export file. Accepts a
                              {keyId: SPKI-DER-base64} map, a
                              [{keyId, publicKey, ...}] list, or the raw
                              GET /v1/verification-keys response envelope
                              (the .data array is unwrapped automatically, and
                              the key statements it carries are walked with
                              the export's). Merged over any keys embedded in
                              the export.
  --require-key-id            Require every entry to reference this keyId.
                              Rejects otherwise-valid exports signed by a
                              retired or unexpected key.
  --require-supplied-keys     Refuse keys embedded in the export: an entry
                              whose only key is the export's own fails. This
                              says where a key came from, not that it is
                              trusted; pin --trust-anchor for that.
  --version, -V               Print this verifier's version and the
                              @agledger/verify-core it runs on.
  --help, -h                  Show this help.

Without --trust-anchor no key is anchored. Every key is taken from the
artifact itself (the dump's vault_signing_keys, the export's embedded keys, or
keys fetched from the same Server), and a key written into the Server's
database alone would verify. Such a run still finds tampering and still exits
0 when nothing fails, but it reports VERIFIED, NOT ANCHORED (JSON verdict
"unanchored"), never a trusted verdict. Ask the operator for the digest of a
vault key: the installer prints it, and signing-key-digest.js derives it.

The key-policy flags (--keys, --require-key-id, --require-supplied-keys)
apply to /audit-export files only; a dump directory carries its own signed key
history and rejects them.

A dump not scoped to one org carries the cert keys itself: each
EPHEMERAL_CERT_ISSUED entry on the platform-ops chain signs its cert's
publicKeyJwk (engines from 1.8.0 on), and a key is used once that chain has
verified clean. An org-scoped dump leaves the platform-ops chain out, and a
per-record /audit-export carries no cert keys, so for those pass --agent-keys.
Where no key is at hand the agent-signature check reports "not checked" and
changes no verdict.

A dump directory must contain:
  audit_vault.ndjson
  vault_checkpoints.ndjson
  vault_signing_keys.ndjson
  vault_key_statements.ndjson
  org_admin_reads.ndjson
  org_admin_reads_checkpoints.ndjson

audit_vault.ndjson is streamed, so vault size is bounded by disk, not memory.

Exit codes:
  0  verified, no failures (read the verdict: trusted with a --trust-anchor,
     unanchored without one)
  1  verification FAILED (the chain, log, or key statements do not hold up)
  2  could NOT verify (input missing, unreadable, or malformed; no verdict)

Codes 1 and 2 mean opposite things. Treat only 1 as evidence of tampering.
`;

/**
 * List a report section's failures, noting how many were withheld. A systemic
 * problem on a large vault produces one failure per entry, so printing them all
 * buries the finding under megabytes of the same line.
 */
function failureLines(failures: readonly Failure[], failureCount: number, indent: string): string[] {
  const lines = failures.map((f) => `${indent}[${f.code}] ${f.message}`);
  const withheld = failureCount - failures.length;
  if (withheld > 0) {
    lines.push(`${indent}... and ${withheld} more not shown (${failureCount} total)`);
  }
  return lines;
}

/** What the text formatters need to know beyond the report itself. */
export interface TextReportOptions {
  /** Whether the caller passed `--agent-keys` (agent cert keys). Default false. */
  agentKeysSupplied?: boolean;
  /** Whether the caller passed `--federation-key` (peer federation keys). Default false. */
  federationKeysSupplied?: boolean;
}

/**
 * verify-core reads every entry of a chain, past a break, and runs the
 * optional checks on each entry that passed the rest; an entry that failed
 * another check is not counted. On a failed run the counters say so.
 */
const COUNTED_ON_SOUND_ENTRIES = ', counted on the entries that passed every other check';

/**
 * One line on the sealed federation messages. Each is held to its body hash
 * and to its entry, then checked under the peer key given for its hub, if
 * one was. `verified` passed under a key, `failed` failed a check (listed
 * below), and the rest came from a hub with no key, which is not a failure.
 */
function federationWireSummary(
  counts: { present: number; verified: number; failed: number },
  keysSupplied: boolean,
  failed = false,
): string {
  const base = `present=${counts.present} verified=${counts.verified} failed=${counts.failed}${failed ? COUNTED_ON_SOUND_ENTRIES : ''}`;
  if (counts.present === 0) return failed ? `${base} (none among them)` : `${base} (none on the chain)`;
  const noKey = counts.present - counts.verified - counts.failed;
  if (noKey === 0 && counts.failed === 0) {
    return `${base} (each hashed, matched to its entry, and signed by the peer key given for its hub)`;
  }
  const parts: string[] = [];
  if (counts.failed > 0) parts.push(`${counts.failed} failed: see the failures below`);
  if (noKey > 0) {
    parts.push(
      keysSupplied
        ? `${noKey} hashed and matched to its entry, from a hub with no --federation-key, so the peer's signature was not checked`
        : `${noKey} hashed and matched to its entry; the peer signatures were NOT checked: pass --federation-key <hubId>=<key> for each peer`,
    );
  }
  return `${base} (${parts.join('; ')})`;
}

/**
 * One line on the agent-signature check, worded by case so a PASS never reads
 * as covering signatures that were not re-verified. `present > verified` on a
 * passing report means some were not checked (no key for their cert, or a
 * caller-asserted identity), never that they failed; on a failing report the
 * failure is also listed. `keysFromChain` counts the cert keys a dump signs
 * itself (always 0 for an export).
 */
function agentSignatureSummary(
  counts: { present: number; verified: number },
  check: CheckApplicability,
  keysSupplied: boolean,
  keysFromChain = 0,
  failed = false,
): string {
  const base = `present=${counts.present} verified=${counts.verified}${failed ? COUNTED_ON_SOUND_ENTRIES : ''}`;
  if (counts.present === 0) return failed ? `${base} (none among them)` : `${base} (none on the chain)`;
  const unverified = counts.present - counts.verified;
  const onChain = `${keysFromChain} cert key${keysFromChain === 1 ? '' : 's'} the dump signs`;
  if (check === 'applied') {
    const against =
      keysFromChain === 0 ? 'the supplied keys' : keysSupplied ? `the supplied keys and the ${onChain}` : `the ${onChain}`;
    return unverified === 0
      ? `${base} (all re-verified against ${against})`
      : `${base} (${unverified} NOT verified: no key for their cert, a caller-asserted identity, or a failure listed in this report)`;
  }
  if (keysSupplied) {
    return `${base} (NOT verified: none of the supplied keys${keysFromChain === 0 ? '' : ` or the ${onChain}`} matches the cert thumbprint sealed with an engine-validated agent signature)`;
  }
  return keysFromChain === 0
    ? `${base} (NOT verified: pass --agent-keys with the agent cert keys to re-verify them)`
    : `${base} (NOT verified: none of the ${onChain} matches; pass --agent-keys with the agent cert keys to re-verify them)`;
}

/**
 * The headline. `unanchored` gets its own words so that a run which found
 * nothing wrong but anchored nothing can never be read, or grepped, as a
 * trusted PASS.
 */
function headline(verdict: Verdict, kind: string, keyTrust: KeyTrustReport): string[] {
  if (verdict === 'trusted') {
    return [
      `[PASS] AGLedger offline verification (${kind})`,
      '  Nothing failed, and every signature was checked under a key the signed key statements',
      '  link to a --trust-anchor you gave.',
    ];
  }
  if (verdict === 'failed') {
    return [
      `[FAIL] AGLedger offline verification (${kind})`,
      '  Verification FAILED: the chain, the read log or the key statements do not hold up.',
      '  Each finding is listed below.',
    ];
  }
  if (keyTrust.status === 'no_anchored_signature') {
    return [
      `[VERIFIED, NOT ANCHORED] AGLedger offline verification (${kind})`,
      '  Nothing failed, but this is NOT a trusted verdict: the --trust-anchor was walked, but no',
      '  signature here verified under a key it anchors. An entry written before the install',
      '  began signing carries no signature, and proves nothing about who wrote it.',
    ];
  }
  return [
    `[VERIFIED, NOT ANCHORED] AGLedger offline verification (${kind})`,
    '  Nothing failed, but this is NOT a trusted verdict: no --trust-anchor was given, so every',
    '  signing key was taken on the word of the artifact itself, and a key written into the',
    '  Server\'s database alone would verify. Ask the operator for the SPKI digest of a vault',
    '  key (the installer prints it; signing-key-digest.js derives it from any key) and',
    '  re-run with --trust-anchor sha256:<hex>.',
  ];
}

/** The key-anchoring section, shared by the dump and export reports. */
function keyTrustLines(keyTrust: KeyTrustReport, indent: string): string[] {
  if (keyTrust.status === 'no_anchor') {
    return [`${indent}status      : NOT RUN (no --trust-anchor given; no key is anchored)`];
  }
  const ids = (list: readonly string[]) => (list.length === 0 ? '(none)' : list.join(', '));
  const unsignedOnly = keyTrust.status === 'no_anchored_signature' ? '; NO signature verified under an anchored key' : '';
  const lines = [
    `${indent}status      : walked from ${keyTrust.anchors.join(', ')} (${keyTrust.order === 'written' ? 'write order' : 'signed order'})${unsignedOnly}`,
    `${indent}anchored    : ${ids(keyTrust.anchoredKeyIds)}`,
    `${indent}unanchored  : ${ids(keyTrust.unanchoredKeyIds)}`,
  ];
  if (keyTrust.undecidedKeyIds.length > 0) {
    lines.push(`${indent}undecided   : ${ids(keyTrust.undecidedKeyIds)} (reached only through a signature this host cannot compute)`);
  }
  lines.push(`${indent}findings    : ${keyTrust.findings.length}`);
  for (const f of keyTrust.findings) {
    lines.push(`${indent}  [${f.code}] ${f.keyId === null ? '' : `key ${f.keyId}: `}${f.detail}`);
  }
  for (const n of keyTrust.notes) {
    lines.push(`${indent}  note: ${n.keyId === null ? '' : `key ${n.keyId}: `}${n.detail}`);
  }
  for (const n of keyTrust.accounted) {
    lines.push(`${indent}  accounted for: ${n.keyId === null ? '' : `key ${n.keyId}: `}${n.detail}`);
  }
  return lines;
}

function accountedChainName(a: AccountedEntry): string {
  if (a.chain === 'record') return `Record ${a.recordId}`;
  if (a.chain === 'admin') return 'Chain admin';
  return `Chain schema:${a.orgId ?? '__platform__'}`;
}

export function formatDumpReportText(report: VerifyReport, options: TextReportOptions = {}): string {
  const lines: string[] = [];
  lines.push(...headline(report.verdict, 'dump', report.keyTrust));
  lines.push('');
  lines.push('key anchoring');
  lines.push(...keyTrustLines(report.keyTrust, '  '));
  lines.push('');
  lines.push('audit_vault chain');
  lines.push(`  records     : ${report.vault.recordCount}`);
  lines.push(`  entries     : ${report.vault.entryCount}`);
  lines.push(`  checkpoints : ${report.vault.checkpointCount}`);
  lines.push(
    `  agent sigs  : ${agentSignatureSummary(report.vault.agentSignatures, report.vault.optionalChecks.agent_signature, options.agentKeysSupplied ?? false, report.vault.certKeysFromChain, report.vault.failureCount > 0)}`,
  );
  lines.push(
    `  peer msgs   : ${federationWireSummary(report.vault.federationWire, options.federationKeysSupplied ?? false, report.vault.failureCount > 0)}`,
  );
  lines.push(`  failures    : ${report.vault.failureCount}`);
  lines.push(...failureLines(report.vault.failures, report.vault.failureCount, '    '));
  if (report.vault.accountedCount > 0) {
    // Signed by a key the operator distrusts, before a key the walk trusts
    // retired it: the distrust entry accounts for them. Not verified and not
    // failures, and listed so nobody reads them as vouched for.
    lines.push(`  accounted for: ${report.vault.accountedCount} (signed by a distrusted key before its retirement; not verified)`);
    lines.push(...report.vault.accounted.map((a) => `    [${a.code}] ${accountedChainName(a)} pos ${a.position} key ${a.keyId}: ${a.detail}`));
    const withheld = report.vault.accountedCount - report.vault.accounted.length;
    if (withheld > 0) lines.push(`    ... and ${withheld} more not shown (${report.vault.accountedCount} total)`);
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
  lines.push(`  failures         : ${report.orgAdminReads.failureCount}`);
  lines.push(
    ...failureLines(report.orgAdminReads.failures, report.orgAdminReads.failureCount, '    '),
  );
  return lines.join('\n');
}

export function formatExportReportText(
  result: VerifyExportResult,
  options: TextReportOptions = {},
): string {
  const lines: string[] = [];
  lines.push(...headline(result.verdict, 'audit-export', result.keyTrust));
  lines.push('');
  lines.push(`  record            : ${result.recordId}`);
  lines.push(`  entries           : ${result.verifiedEntries}/${result.totalEntries} verified`);
  lines.push(
    `  signature coverage: signed=${result.signatureCoverage.signed} unsigned=${result.signatureCoverage.unsigned} skipped=${result.signatureCoverage.skipped}`,
  );
  lines.push(
    `  key provenance    : supplied=${result.keyProvenance.supplied} embedded=${result.keyProvenance.embedded}`,
  );
  // Where a key came from is not whether it is trusted: a full re-sign with a
  // swapped key passes against the export's own keys and against keys fetched
  // from the same Server alike. Only the walk from a pin says a key is trusted,
  // so that is what the report states beside the provenance counters.
  lines.push('  key anchoring');
  lines.push(...keyTrustLines(result.keyTrust, '    '));
  lines.push(
    `  agent signatures  : ${agentSignatureSummary(result.agentSignatures, result.optionalChecks.agent_signature, options.agentKeysSupplied ?? false, 0, !result.valid)}`,
  );
  lines.push(
    `  peer messages     : ${federationWireSummary(result.federationWire, options.federationKeysSupplied ?? false, !result.valid)}`,
  );
  if (result.brokenAt) {
    lines.push(`  broken at pos ${result.brokenAt.position}: [${result.brokenAt.code}] ${result.brokenAt.detail ?? ''}`);
  }
  // A PASS must not be read as vouching for unsigned display projections
  // (e.g. actorDisplayName). The attribution the export's guide points at
  // instead, actorOwnerId/actorId, IS signature-covered, so say whether this
  // run actually checked it rather than leaving the reader to assume.
  if (result.unsignedProjectionFields.length > 0) {
    // `applied` says the check RAN, not that it passed, so a failed run must
    // not be told its attribution agrees: on a FAIL the verdict above is the
    // only thing this note may defer to.
    const attribution =
      result.optionalChecks.actor_attribution !== 'applied'
        ? 'Attribution (actorId/actorOwnerId) carries no signed actor claim in this export, so it was NOT cross-checked.'
        : result.valid
          ? 'Attribution (actorId/actorOwnerId/actorRole) was cross-checked against the signed actor claim and agrees.'
          : 'Attribution (actorId/actorOwnerId/actorRole) is cross-checked against the signed actor claim, and this run did not verify, so nothing above is vouched for.';
    lines.push(
      `  note              : ${result.unsignedProjectionFields.length} unsigned display projection field(s) (${result.unsignedProjectionFields.join(', ')}) are NOT signature-covered. ${attribution}`,
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

/**
 * Report "no verdict was reached" in whichever format the caller asked for.
 * Under `--report-format json` the message still has to arrive as JSON: a
 * machine consumer that gets a bare line of prose cannot tell an unreadable
 * dump from a broken chain, which is the whole point of exit code 2.
 */
function cannotVerify(message: string, format: ParsedArgs['reportFormat']): CliResult {
  if (format === 'json') {
    const body: CannotVerifyReport = { ok: false, error: { kind: 'input', message } };
    return { exitCode: EXIT_CANNOT_VERIFY, stdout: JSON.stringify(body, null, 2) + '\n', stderr: '' };
  }
  return { exitCode: EXIT_CANNOT_VERIFY, stdout: '', stderr: `${message}\n` };
}

/** A pin parser's message, named by the flag that carried the value. */
function flagMessage(message: string): string {
  return message
    .replace(/^trustAnchors entry /, '--trust-anchor ')
    .replace(/^distrustedKeys entry /, '--distrusted-key ')
    .replace(/^distrustedKeys names /, '--distrusted-key names ')
    .replace(/^(sha256:[0-9a-f]{64}) is a trust anchor and a distrusted key with no instant,/, '$1 is a --trust-anchor and a --distrusted-key with no instant,');
}

/**
 * verify-core words a finding, note or failure for a library caller, so its
 * advice names options (`give distrustedKeys sha256:<hex>@<instant>`,
 * `pin sha256:<hex> in trustAnchors`). A CLI user gives those as flags, so the report
 * names the flag; the library's own result objects are left as they are.
 */
const OPTION_FLAGS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\badd (sha256:[0-9a-f]{64}) to distrustedKeys\b/g, 'add --distrusted-key $1'],
  [/\bis in distrustedKeys\b/g, 'is given as a --distrusted-key'],
  [/\bin trustAnchors\b/g, 'with --trust-anchor'],
  [/\bNo trustAnchors were given\b/g, 'No --trust-anchor was given'],
  [/\bdistrustedKeys\b/g, '--distrusted-key'],
  [/\btrustAnchors\b/g, '--trust-anchor'],
  [/\brequireSuppliedKeys\b/g, '--require-supplied-keys'],
  [/\brequireKeyId\b/g, '--require-key-id'],
  [/\bagentKeys\b/g, '--agent-keys'],
  [/\bfederationKeys\b/g, '--federation-key'],
];

/** One prose string from a report, its option names given as this CLI's flags. */
export function flagWording(text: string): string {
  return OPTION_FLAGS.reduce((s, [pattern, flag]) => s.replace(pattern, flag), text);
}

/**
 * The prose a key-trust report carries, worded by {@link flagWording}: its
 * detail and each finding, note and accounted-for detail. Ids, digests and
 * instants are data and pass through as they are.
 */
function keyTrustWithFlags(keyTrust: KeyTrustReport): KeyTrustReport {
  const prose = <T extends { detail: string }>(item: T): T => ({ ...item, detail: flagWording(item.detail) });
  return {
    ...keyTrust,
    detail: flagWording(keyTrust.detail),
    findings: keyTrust.findings.map(prose),
    notes: keyTrust.notes.map(prose),
    accounted: keyTrust.accounted.map(prose),
  };
}

/** An export result with its prose (the details verify-core writes) worded by {@link flagWording}. */
export function exportResultWithFlags(result: VerifyExportResult): VerifyExportResult {
  const detail = <T extends { detail?: string }>(item: T): T =>
    item.detail === undefined ? item : { ...item, detail: flagWording(item.detail) };
  return {
    ...result,
    ...(result.brokenAt ? { brokenAt: detail(result.brokenAt) } : {}),
    entries: result.entries.map(detail),
    keyTrust: keyTrustWithFlags(result.keyTrust),
  };
}

/** A dump report with its prose (failure messages and details) worded by {@link flagWording}. */
export function dumpReportWithFlags(report: VerifyReport): VerifyReport {
  const failure = (f: Failure): Failure => ({ ...f, message: flagWording(f.message) });
  return {
    ...report,
    keyTrust: keyTrustWithFlags(report.keyTrust),
    vault: {
      ...report.vault,
      failures: report.vault.failures.map(failure),
      accounted: report.vault.accounted.map((a) => ({ ...a, detail: flagWording(a.detail) })),
    },
    orgAdminReads: { ...report.orgAdminReads, failures: report.orgAdminReads.failures.map(failure) },
  };
}

const FEDERATION_KEY_SHAPE =
  'Each --federation-key is <hubId>=<key>: the peer\'s hub id, then its Ed25519 federation key as base64 SPKI DER or base64 of the raw 32 bytes, as its operator gives it.';

/**
 * `--federation-key` values into the `{ [hubId]: key }` map verify-core takes,
 * or the usage-error message. Each value is checked here, before any
 * verification runs, so a bad key is reported as a bad key rather than as a
 * verdict.
 */
export function parseFederationKeys(values: readonly string[]): Record<string, string> | string {
  const out: Record<string, string> = {};
  for (const value of values) {
    const at = value.indexOf('=');
    const hubId = at === -1 ? '' : value.slice(0, at).trim();
    const key = at === -1 ? '' : value.slice(at + 1).trim();
    if (hubId === '' || key === '') return `Invalid --federation-key ${JSON.stringify(value)}: ${FEDERATION_KEY_SHAPE}`;
    if (normalizeFederationKey(key) === null) {
      return `Invalid --federation-key for hub ${hubId}: the key is not an Ed25519 public key. ${FEDERATION_KEY_SHAPE}`;
    }
    if (hubId in out) return `--federation-key names hub ${hubId} twice; give each peer one key.`;
    out[hubId] = key;
  }
  return out;
}

/** The `version` in a package.json, or `unknown` when it cannot be read. */
function packageVersion(packageJson: URL): string {
  try {
    const { version } = JSON.parse(readFileSync(packageJson, 'utf-8')) as { version?: unknown };
    return typeof version === 'string' ? version : 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * `agledger-verify <version> (@agledger/verify-core <version>)`, so an audit
 * record can name the verifier that produced it. verify-core's exports map
 * hides its package.json, so it is found from the resolved entry point.
 */
function versionLine(): string {
  const own = packageVersion(new URL('../package.json', import.meta.url));
  let core = 'unknown';
  try {
    core = packageVersion(new URL('../package.json', import.meta.resolve('@agledger/verify-core')));
  } catch {
    // Not resolvable from here; the version stays unknown.
  }
  return `agledger-verify ${own} (@agledger/verify-core ${core})\n`;
}

export function runCli(argv: readonly string[]): CliResult {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    // Format is not known yet, so usage errors stay plain text.
    return {
      exitCode: EXIT_CANNOT_VERIFY,
      stdout: '',
      stderr: `${(err as Error).message}\n\n${HELP_TEXT}`,
    };
  }
  if (parsed.showHelp) {
    return { exitCode: EXIT_OK, stdout: HELP_TEXT, stderr: '' };
  }
  if (parsed.showVersion) {
    return { exitCode: EXIT_OK, stdout: versionLine(), stderr: '' };
  }
  if (!parsed.target) {
    return { exitCode: EXIT_CANNOT_VERIFY, stdout: '', stderr: `Missing <target>.\n\n${HELP_TEXT}` };
  }

  const hasKeyPolicyFlags =
    parsed.keys !== null || parsed.requireKeyId !== null || parsed.requireSuppliedKeys;

  // Parsed before anything is read, so a mistyped pin is a usage error and
  // never a verdict: a run that silently dropped it would read as unanchored.
  let trustAnchors: string[];
  let distrustedKeys: DistrustedKey[];
  try {
    trustAnchors = parseTrustAnchors(parsed.trustAnchors).map((d) => `sha256:${d}`);
    distrustedKeys = parseDistrustedKeys(parsed.distrustedKeys);
  } catch (err) {
    if (err instanceof TypeError) return cannotVerify(flagMessage(err.message), parsed.reportFormat);
    throw err;
  }
  if (distrustedKeys.length > 0 && trustAnchors.length === 0) {
    return cannotVerify(
      '--distrusted-key acts only inside the key-statement walk, which runs from --trust-anchor; pass the pin as well.',
      parsed.reportFormat,
    );
  }
  try {
    assertNotPinnedAndDistrusted(trustAnchors, distrustedKeys);
  } catch (err) {
    if (err instanceof TypeError) return cannotVerify(flagMessage(err.message), parsed.reportFormat);
    throw err;
  }
  if (!existsSync(parsed.target)) {
    return cannotVerify(`Cannot read ${parsed.target}: no such file or directory.`, parsed.reportFormat);
  }

  let agentKeys: AgentPublicKeyJwk[] | undefined;
  if (parsed.agentKeys !== null) {
    const loaded = loadAgentKeys(parsed.agentKeys);
    if (typeof loaded === 'string') return cannotVerify(loaded, parsed.reportFormat);
    agentKeys = loaded;
  }

  let federationKeys: Record<string, string> | undefined;
  if (parsed.federationKeys.length > 0) {
    const loaded = parseFederationKeys(parsed.federationKeys);
    if (typeof loaded === 'string') return cannotVerify(loaded, parsed.reportFormat);
    federationKeys = loaded;
  }

  // Directory -> full-vault dump.
  if (isDirectory(parsed.target)) {
    if (hasKeyPolicyFlags) {
      return cannotVerify(
        '--keys / --require-key-id / --require-supplied-keys apply to /audit-export files only; a dump directory carries its own signed key history (vault_signing_keys.ndjson and vault_key_statements.ndjson). Pin it with --trust-anchor.',
        parsed.reportFormat,
      );
    }
    let report: VerifyReport;
    try {
      // Streamed, so a multi-GB audit_vault.ndjson is bounded by disk rather
      // than by Node's max string length.
      report = verifyDumpStreaming(parsed.target, undefined, { agentKeys, federationKeys, trustAnchors, distrustedKeys });
    } catch (err) {
      // A TypeError here is the walk refusing a statement file it cannot
      // order (rows with and without created_at): no verdict was reached.
      if (err instanceof DumpReadError || err instanceof TypeError) {
        return cannotVerify(err.message, parsed.reportFormat);
      }
      throw err;
    }
    report = dumpReportWithFlags(report);
    const stdout =
      parsed.reportFormat === 'json'
        ? JSON.stringify(report, null, 2) + '\n'
        : formatDumpReportText(report, { agentKeysSupplied: agentKeys !== undefined, federationKeysSupplied: federationKeys !== undefined }) + '\n';
    return { exitCode: EXIT_BY_VERDICT[report.verdict], stdout, stderr: '' };
  }

  // File -> parse JSON, branch on exportMetadata.
  let raw: string;
  try {
    raw = readFileSync(parsed.target, 'utf-8');
  } catch (err) {
    return cannotVerify((err as Error).message, parsed.reportFormat);
  }
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(raw);
  } catch (err) {
    return cannotVerify(
      `Invalid JSON in ${parsed.target}: ${(err as Error).message}`,
      parsed.reportFormat,
    );
  }
  if (!looksLikeAuditExport(parsedJson)) {
    return {
      exitCode: EXIT_CANNOT_VERIFY,
      stdout: '',
      stderr: `${parsed.target} is neither a dump directory nor an /audit-export JSON document (expected exportMetadata + entries).\n\n${HELP_TEXT}`,
    };
  }

  let publicKeys: Record<string, string> | ReadonlyArray<SuppliedKeyEntry> | undefined;
  if (parsed.keys !== null) {
    let rawKeys: string;
    try {
      rawKeys = readFileSync(parsed.keys, 'utf-8');
    } catch (err) {
      return cannotVerify((err as Error).message, parsed.reportFormat);
    }
    let parsedKeys: unknown;
    try {
      parsedKeys = JSON.parse(rawKeys);
    } catch (err) {
      return cannotVerify(
        `Invalid JSON in ${parsed.keys}: ${(err as Error).message}`,
        parsed.reportFormat,
      );
    }
    publicKeys = unwrapKeys(parsedKeys);
  }

  // verify-core throws TypeError when an input's shape is wrong: the --keys
  // file (e.g. {keyId: 42}, [null]), or the export itself (e.g. a
  // signingKeyStatements array). Surface it as a could-not-verify rather than a
  // stack trace, and add the --keys shape only when the --keys file is what
  // verify-core refused.
  let result: VerifyExportResult;
  try {
    result = verifyAuditExport(parsedJson, {
      publicKeys,
      requireKeyId: parsed.requireKeyId ?? undefined,
      requireSuppliedKeys: parsed.requireSuppliedKeys,
      agentKeys,
      federationKeys,
      trustAnchors,
      distrustedKeys,
    });
  } catch (err) {
    if (err instanceof TypeError) {
      const keysFileRefused = publicKeys !== undefined && err.message.startsWith('verifyAuditExport: publicKeys');
      return cannotVerify(
        keysFileRefused
          ? `${err.message}\nThe --keys file must be a {keyId: SPKI-DER-base64} map or a list of {keyId, publicKey, ...} entries (the .data list from /v1/verification-keys).`
          : `${parsed.target}: ${err.message}`,
        parsed.reportFormat,
      );
    }
    throw err;
  }
  // verify-core's result, verdict first (`valid` alone is true on a run that
  // anchored nothing), with its advice naming the flags.
  result = exportResultWithFlags(result);
  const { verdict, ...rest } = result;
  const stdout =
    parsed.reportFormat === 'json'
      ? JSON.stringify({ verdict, ...rest }, null, 2) + '\n'
      : formatExportReportText(result, { agentKeysSupplied: agentKeys !== undefined, federationKeysSupplied: federationKeys !== undefined }) + '\n';
  return { exitCode: EXIT_BY_VERDICT[verdict], stdout, stderr: '' };
}

/**
 * Accept the raw `GET /v1/verification-keys` response shape. That endpoint
 * returns an envelope `{ data: [{ keyId, publicKey, ... }], ... }`, not the
 * bare array its consumers expect, so unwrap `.data` so a file saved straight
 * from the endpoint verifies without hand-editing (same behavior as
 * `agledger verify --keys`). A bare `[{keyId, publicKey}]` list or a
 * `{keyId: base64}` map passes through untouched; verify-core then validates
 * the shape and throws on anything else.
 */
function unwrapKeys(raw: unknown): Record<string, string> | ReadonlyArray<SuppliedKeyEntry> {
  if (
    raw &&
    typeof raw === 'object' &&
    !Array.isArray(raw) &&
    Array.isArray((raw as { data?: unknown }).data)
  ) {
    return (raw as { data: ReadonlyArray<SuppliedKeyEntry> }).data;
  }
  return raw as Record<string, string> | ReadonlyArray<SuppliedKeyEntry>;
}

const AGENT_KEYS_SHAPE =
  'The --agent-keys file must hold Ed25519 public-key JWKs ({"kty":"OKP","crv":"Ed25519","x":"<base64url>"}): one JWK, a list of them, or a {"keys":[...]} JWK Set, where an entry may wrap its key as {"publicKeyJwk":{...}}.';

/**
 * Read an `--agent-keys` file into a list of JWKs, or return the usage-error
 * message. Accepts the same shapes as `agledger verify --agent-keys`: a single
 * JWK, a list of JWKs, or a `{keys: [...]}` JWK Set, where an entry that wraps
 * its key as `{ publicKeyJwk: {...} }` (how an agent records the key it sent at
 * cert exchange) is unwrapped. Every key is validated here, before any
 * verification runs, so a bad file is reported as a bad file in both modes
 * rather than as a verdict.
 */
export function loadAgentKeys(path: string): AgentPublicKeyJwk[] | string {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf-8'));
  } catch (err) {
    return `Cannot read --agent-keys file ${path}: ${(err as Error).message}`;
  }
  const list: unknown[] = Array.isArray(raw)
    ? raw
    : raw && typeof raw === 'object' && Array.isArray((raw as { keys?: unknown }).keys)
      ? (raw as { keys: unknown[] }).keys
      : [raw];
  if (list.length === 0) {
    return `The --agent-keys file ${path} holds no keys. ${AGENT_KEYS_SHAPE}`;
  }
  const jwks = list.map((entry) =>
    entry && typeof entry === 'object' && 'publicKeyJwk' in entry
      ? (entry as { publicKeyJwk: unknown }).publicKeyJwk
      : entry,
  ) as AgentPublicKeyJwk[];
  try {
    buildAgentKeyRegistry(jwks);
  } catch (err) {
    if (err instanceof TypeError) {
      return `Invalid --agent-keys file ${path}: ${err.message.replace(/^agentKeys\[(\d+)\]/, 'entry $1')}\n${AGENT_KEYS_SHAPE}`;
    }
    throw err;
  }
  return jwks;
}
