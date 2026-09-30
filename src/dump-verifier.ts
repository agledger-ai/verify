/**
 * Pure verification functions over an already-loaded dump. No I/O, no DB, no
 * global state.
 *
 * The per-record (and per-org schema-event) hash-chain walk is delegated
 * wholesale to `@agledger/verify-core`'s `verifyChain`, the single body of
 * logic the SDK /verify subpath, the CLI, and the MCP server all run. Each
 * grouped chain's rows are adapted into the core's `NormalizedEntry` shape,
 * carrying the dump-only inputs the export wire cannot: the binding-integrity
 * payload, the OIDC-actor columns, and the per-entry write time. The signing
 * key registry is built from the dump's `vault_signing_keys` with their
 * temporal windows, so binding-integrity, OIDC-actor cross-check, AND
 * temporal key-validity (CHAIN_KEY_NOT_YET_ACTIVE / CHAIN_KEY_EXPIRED) all come
 * from the core for free.
 *
 * Key anchoring is verify-core's walk too (`walkDumpKeys`). With
 * `trustAnchors`, the dump's `vault_key_statements` are walked in write order
 * (`created_at`, then the producer's `id` order) from the pinned SPKI digests,
 * and each key in the registry is marked anchored, unanchored or undecided, an
 * anchored key carrying the window its statements sign. Entries, vault
 * checkpoints, read-log leaves and read-log checkpoints under an unanchored key
 * fail CHAIN_SIGNING_KEY_UNANCHORED, CHECKPOINT_KEY_UNANCHORED,
 * TENANT_READ_KEY_UNANCHORED and TENANT_CHECKPOINT_KEY_UNANCHORED, as the
 * engine's scan grades them. Without anchors no walk runs, the registry rows
 * are taken as they stand, and a pass carries the verdict `unanchored`.
 *
 * What stays LOCAL to this package is the dump-structural work the core does
 * not model: the vault-checkpoint cross-check against the live chain, and the
 * org_admin_reads log (RFC 9162 leaf hashes and tree heads, via verify-core's
 * orgReadLeafHash / orgReadMerkleRoot) with its signed-tree-head and
 * fork-detection passes. They emit the canonical CHECKPOINT_* / TENANT_* codes.
 *
 * Unsigned rows follow the engine's one rule everywhere: the instant the
 * install began signing is the earliest `activated_at` in
 * `vault_signing_keys` (retired keys included; the dump always carries the
 * whole registry, even when scoped to one org). An unsigned chain entry, vault
 * checkpoint, read-log leaf or read-log checkpoint written at or after it is a
 * break, and so is an unsigned entry or leaf that follows a signed one in its
 * chain or log. Anything earlier is reduced coverage, not a break.
 *
 * The agent-signature check needs the cert public keys. A dump not scoped to
 * one org carries them: each `EPHEMERAL_CERT_ISSUED` entry on the platform-ops
 * chain signs its cert's `publicKeyJwk` (engines from 1.8.0 on). They are
 * taken only from a chain this walk has itself verified clean, entry
 * signature included, and added to any keys the caller passes as `agentKeys`.
 *
 * Fail-closed posture (security review):
 *   - A dump with zero vault entries is CHAIN_EMPTY, never a silent pass.
 *   - A vault entry lacking `cose_sign1` is a pre-2.0 shape -> UNSUPPORTED_FORMAT;
 *     we do not parse it best-effort.
 *   - Temporal key-validity is enforced by feeding each entry's created_at and
 *     each key's window (signed, once anchored) into verifyChain.
 *   - A report with no `trustAnchors` never reads as trusted: a pass without
 *     them carries the verdict `unanchored`.
 */
import {
  applyKeyTrust,
  buildAgentKeyRegistry,
  buildKeyRegistry,
  computeKeyTrust,
  decodeCoseSign1,
  decodePredicate,
  describeUnsupportedAlgorithm,
  earliestKeyActivation,
  ed25519JwkThumbprint,
  ed25519JwkToSpki,
  extractKid,
  keyStatementFromDumpRow,
  orgReadLeafHash,
  orgReadMerkleRoot,
  reportKeyTrust,
  trustKeyFromDumpRow,
  verifyChain,
  verifyCoseSign1,
  writtenWhileSigning,
  type AgentPublicKeyJwk,
  type ChainResult,
  type CheckApplicability,
  type DistrustedKey,
  type FailureCode,
  type KeyRegistry,
  type KeyTrust,
  type KeyTrustReport,
  type NormalizedEntry,
  type OptionalCheck,
  type VerificationKey,
} from '@agledger/verify-core';
import type {
  Dump,
  Failure,
  KeyStatementDump,
  SigningKeyDump,
  OrgAdminReadDump,
  OrgAdminReadsCheckpointDump,
  TenantAdminReadsReport,
  VaultChainsReport,
  VaultCheckpointDump,
  VaultEntryDump,
  VerifyReport,
} from './types.js';
import { decodeSignedClaim, uuidSubjectDigest } from './claim.js';

/** Options for the vault-chain walk. */
export interface VaultChainOptions {
  /**
   * Ed25519 public keys of agent ephemeral certs, as JWKs: the `publicKeyJwk`
   * an agent sent to `POST /v1/auth/oidc/cert`, also the `cnf.jwk` claim inside
   * the `certJws`. Needed for certs the dump does not sign a key for: every
   * cert on an org-scoped dump (which leaves out the platform-ops chain), and
   * certs issued by an engine older than 1.8.0. The keys a dump does carry
   * are used without being passed here. Where an entry's signed
   * payload carries an engine-validated `predicate.on_behalf_of.agent_signature`
   * whose sealed cert thumbprint matches one of these keys, the signature is
   * re-verified offline; one that does not verify fails
   * `CHAIN_AGENT_SIGNATURE_INVALID`. A key is matched only through the
   * thumbprint the entry signed, so a key for another cert matches nothing.
   * Anything that is not an Ed25519 JWK throws `TypeError`.
   */
  agentKeys?: ReadonlyArray<AgentPublicKeyJwk>;
}

/** Inputs to the key-statement walk (see {@link walkDumpKeys}). */
export interface KeyTrustOptions {
  /**
   * SPKI digests of vault keys held or taken out of band, `sha256:<64 hex>`:
   * the installer prints the first key's, and the Server's
   * `signing-key-digest.js` derives one from any key. The dump's key
   * statements are walked from them, and a key they do not reach anchors
   * nothing it signed. Nothing in the dump is ever an anchor. Omitted or
   * empty, no walk runs and a pass carries the verdict `unanchored`.
   */
  trustAnchors?: readonly string[];
  /**
   * The operator's `VAULT_DISTRUSTED_KEYS`: `sha256:<64 hex>`, optionally
   * `@<RFC 3339 instant>`, as strings or parsed entries. What such a key
   * stored from the instant on (with none, from the retirement a trusted key
   * signed for it) counts for nothing in the walk. Requires `trustAnchors`.
   */
  distrustedKeys?: ReadonlyArray<string | DistrustedKey>;
}

/** Options for {@link verifyDump} and `verifyDumpStreaming`. */
export interface VerifyDumpOptions extends VaultChainOptions, KeyTrustOptions {}

/**
 * The dump's key registry after the trust walk, shared by the vault and
 * read-log passes so both grade against the same verdict on each key.
 */
export interface DumpKeyTrust {
  /** Every `vault_signing_keys` row, marked with the walk's `trust` when one ran. */
  registry: KeyRegistry;
  report: KeyTrustReport;
  /**
   * When the install began signing: the earliest `activated_at` across the
   * registry rows (retired keys included, as the engine's `min(activated_at)`
   * reads them) and, once the walk ran, across the activations the anchored
   * keys' statements sign.
   */
  signingSince: string | null;
}

/**
 * Upper bound on failures carried in a report. A systemic problem on a large
 * vault yields one failure per entry, so an uncapped list is both a multi-GB
 * allocation and an unreadable report. The sink keeps the first
 * MAX_REPORTED_FAILURES as a sample and counts every one.
 */
export const MAX_REPORTED_FAILURES = 1000;

class FailureSink {
  readonly listed: Failure[] = [];
  count = 0;

  push(failure: Failure): void {
    this.count++;
    if (this.listed.length < MAX_REPORTED_FAILURES) this.listed.push(failure);
  }
}

/**
 * Build the dump's key registry and, given `trustAnchors`, run verify-core's
 * trust walk over its key statements in write order, marking each key
 * anchored, unanchored or undecided. Throws `TypeError` on a malformed anchor
 * or distrusted key, on `distrustedKeys` without `trustAnchors`, and on a
 * statement file the walk cannot order (rows with and without `created_at`).
 */
export function walkDumpKeys(
  signingKeys: readonly SigningKeyDump[],
  keyStatements: readonly KeyStatementDump[] = [],
  options: KeyTrustOptions = {},
): DumpKeyTrust {
  const anchors = options.trustAnchors ?? [];
  const distrusted = options.distrustedKeys ?? [];
  let registry = buildVaultKeyRegistry(signingKeys);
  let trust: KeyTrust | null = null;
  if (anchors.length > 0) {
    trust = computeKeyTrust({
      keys: signingKeys.map(trustKeyFromDumpRow),
      statements: keyStatements.map(keyStatementFromDumpRow),
      trustAnchors: anchors,
      distrustedKeys: distrusted,
    });
    registry = applyKeyTrust(registry, trust);
  } else if (distrusted.length > 0) {
    throw new TypeError('distrustedKeys act only inside the key-statement walk, which runs from trustAnchors; pass trustAnchors as well.');
  }
  // The registry's activated_at columns are unsigned: a writer who strips or
  // moves them later would switch the unsigned-row rule off. With a walk, the
  // activations the anchored keys' statements sign count too, and the earliest
  // of all of them stands, so neither source can loosen the rule.
  const signed = trust === null ? [] : [...trust.byDigest.values()].filter((k) => k.trusted);
  const signingSince = earliestKeyActivation([
    ...signingKeys.map((k) => ({ activatedAt: k.activated_at ?? null })),
    ...signed,
  ]);
  return { registry, report: reportKeyTrust(registry, trust, null), signingSince };
}

function buildVaultKeyRegistry(keys: readonly SigningKeyDump[]): KeyRegistry {
  const verificationKeys: VerificationKey[] = keys.map((k) => ({
    keyId: k.key_id,
    spkiBase64: k.public_key,
    // The registry row's DECLARED algorithm. verify-core cross-checks it
    // against what the SPKI key material actually commits to; a row that lies
    // about its own key fails CHAIN_ALG_MISMATCH.
    algorithm: k.algorithm,
    source: 'embedded',
    activatedAt: k.activated_at,
    retiredAt: k.retired_at ?? null,
  }));
  return buildKeyRegistry(verificationKeys);
}

/** The entry type that records a cert's issuance, with its public key signed in. */
const CERT_ISSUED = 'EPHEMERAL_CERT_ISSUED';

/**
 * Add to `registry` the cert public keys a verified chain signs, and return how
 * many were new. Called only for a chain that verified with no failure, its
 * checkpoints included, and reads only entries whose vault signature checked
 * `ok`, so every key taken is one the engine signed and nobody changed since.
 * The key is read from the signed predicate, not the row copy. It is filed
 * under its own RFC 7638 thumbprint, which is how a sealed agent signature
 * names its cert, so a key can only ever check the signatures made under it.
 */
function harvestCertKeys(
  chain: readonly VaultEntryDump[],
  result: ChainResult,
  registry: Map<string, string>,
): number {
  let added = 0;
  chain.forEach((row, i) => {
    if (result.entries[i]?.signature !== 'ok') return;
    const parts = decodeCoseSign1(Buffer.from(row.cose_sign1, 'base64'));
    const predicate = parts ? decodePredicate(parts.payloadBstr) : null;
    if (predicate?.['entry_type'] !== CERT_ISSUED) return;
    const payload = predicate['payload'];
    const jwk =
      payload !== null && typeof payload === 'object' && !Array.isArray(payload)
        ? (payload as Record<string, unknown>)['publicKeyJwk']
        : undefined;
    const thumbprint = ed25519JwkThumbprint(jwk);
    const spki = ed25519JwkToSpki(jwk);
    if (thumbprint === null || spki === null || registry.has(thumbprint)) return;
    registry.set(thumbprint, spki);
    added++;
  });
  return added;
}


/**
 * The kid an unsigned COSE_Sign1 carries, as the engine writes it (eight zero
 * bytes, hex). A read-log leaf has no signing-key column, so the envelope's
 * kid is the only unsigned marker it has.
 */
const UNSIGNED_KID = '0'.repeat(16);

/**
 * Compare an envelope's signed claim with what its row says, field by field,
 * and name the first that differs: `null` when every one agrees. An envelope
 * that does not decode as a claim is named as such. The row columns are what
 * the hash and root cross-checks read, so without this a rewritten column
 * beside an intact envelope, or a fabricated row over any envelope, passed.
 */
function claimDisagreement(
  coseSign1: string,
  expect: (claim: NonNullable<ReturnType<typeof decodeSignedClaim>>) => Array<[string, unknown, unknown]>,
): string | null {
  const claim = decodeSignedClaim(Buffer.from(coseSign1, 'base64'));
  if (claim === null) return 'cose_sign1 does not decode as a signed AGLedger claim';
  for (const [field, signed, row] of expect(claim)) {
    if (signed !== row) return `the signed ${field} ${JSON.stringify(signed ?? null)} is not the row's ${JSON.stringify(row ?? null)}`;
  }
  return null;
}

/**
 * Look up the key a checkpoint or read-log row names and apply the walk's
 * verdict on it, in the engine's order: a key the registry does not hold, then
 * one nothing anchors, then one only a signature this host cannot compute
 * reaches. Returns the key to verify under, or the failure to report.
 */
function signingKeyFor(
  registry: KeyRegistry,
  keyId: string,
  unanchoredCode: FailureCode,
  at: string,
  what: string,
): VerificationKey | { code: FailureCode; message: string } {
  const key = registry.get(keyId);
  if (!key) return { code: 'CHAIN_SIGNATURE_MISSING_KEY', message: `${at}: ${what} "${keyId}" not in dumped key registry` };
  if (key.trust === 'unanchored') {
    return {
      code: unanchoredCode,
      message: `${at}: ${what} "${keyId}" is in the dumped key registry, but no signed key statement links it to a trust anchor, so a row written into the database alone could have put it there`,
    };
  }
  if (key.trust === 'undecided') {
    return {
      code: 'CHAIN_UNSUPPORTED_ALGORITHM',
      message: `${at}: the signature could NOT BE CHECKED. Key ${keyId} is reached only through a key statement signed under an algorithm this host cannot compute; verify the dump on a host that can`,
    };
  }
  return key;
}

/**
 * The chain identity of one vault row. Two chain shapes exist in `audit_vault`:
 *   - **Per-record** (record_id NOT NULL): the normal lifecycle chain for one
 *     record. Group key = record_id.
 *   - **Per-enterprise schema-event** (record_id IS NULL): SCHEMA_REGISTERED /
 *     SCHEMA_IMPORTED / SCHEMA_DIGEST_MISMATCH entries keyed by `payload.orgId`.
 *     Group key = `schema:${orgId ?? '__platform__'}`.
 *
 * Identity source (v0.23.2+): the dump tool emits an explicit `chain_key`
 * column carrying the canonical group identity. Legacy fallback for pre-v0.23.2
 * dumps reconstructs it from record_id + payload.orgId.
 */
function chainKeyOf(e: VaultEntryDump): string {
  return (
    e.chain_key ??
    (e.record_id !== null
      ? e.record_id
      : `schema:${(e.payload?.['orgId'] as string | undefined) ?? '__platform__'}`)
  );
}

/**
 * The chain identity of one checkpoint, which is NOT always its `record_id`.
 * A schema chain's checkpoint carries a derived UUIDv8 in `record_id` (the
 * engine needs a non-null uuid for a chain whose rows have none), so joining on
 * that column strands the checkpoint and reports CHECKPOINT_ROW_MISSING against
 * a perfectly healthy vault. The producer emits `chain_key` to carry the real
 * identity; fall back to `record_id` for dumps taken before it did, which is
 * correct for every chain except schema chains.
 */
function checkpointChainKeyOf(cp: VaultCheckpointDump): string {
  return cp.chain_key ?? cp.record_id;
}

/**
 * How a chain is named in failure messages. A per-record chain key IS a record
 * id, so "Record <uuid>" is a lookup an auditor can act on. A schema chain
 * key is not: labelling it that way sent auditors to /v1/records/{id} for a
 * 404, so it is named as the chain it actually is.
 */
function chainLabel(chainKey: string): string {
  return chainKey.startsWith('schema:') ? `Chain ${chainKey}` : `Record ${chainKey}`;
}

/** Adapt a dump vault row into the verify-core normalized entry shape, carrying
 *  the dump-only inputs (binding, oidcActor, actorAttribution, createdAt). */
function toNormalizedEntry(scopeId: string, e: VaultEntryDump): NormalizedEntry {
  return {
    scopeId,
    chainPosition: e.chain_position,
    payloadHash: e.payload_hash,
    previousHash: e.previous_hash,
    coseSign1: e.cose_sign1,
    signingKeyId: e.signing_key_id,
    createdAt: e.created_at,
    binding: {
      recordId: e.record_id,
      entryType: e.entry_type,
      payload: e.payload,
    },
    oidcActor: {
      iss: e.actor_oidc_iss ?? null,
      sub: e.actor_oidc_sub ?? null,
      synthesized: e.actor_oidc_synthesized,
    },
    // The actor columns a report displays as "who did this" are
    // signature-covered (CWT_Claims label 15 -> -65539), so the core
    // cross-checks them rather than taking them on trust. Required in the
    // dump shape, so this check is always applicable on the dump path.
    actorAttribution: {
      actorId: e.actor_key_id,
      actorRole: e.actor_role,
      actorOwnerId: e.actor_owner_id,
    },
  };
}

/** Translate a verify-core ChainResult into this package's flat Failure list,
 *  preserving the canonical code + a dump-flavored message. */
function collectChainFailures(scopeId: string, result: ChainResult, failures: FailureSink): void {
  for (const entry of result.entries) {
    if (entry.valid || !entry.failure) continue;
    failures.push({
      code: entry.failure.code,
      message: `${chainLabel(scopeId)} pos ${entry.position}: ${entry.failure.detail}`,
      scopeId,
      position: entry.position,
    });
  }
}

/**
 * Cross-check one chain's checkpoints against its rows. vault_checkpoints
 * survives audit_vault TRUNCATE, so a chain shorter than (or hash-mismatched
 * with) its anchor is evidence of out-of-band tampering. Dump-structural, so it
 * stays local rather than moving into verify-core.
 *
 * `chain` must already be sorted by chain_position; the anchor is looked up
 * positionally.
 */
function verifyChainCheckpoints(
  chain: readonly VaultEntryDump[],
  checkpoints: readonly VaultCheckpointDump[],
  keys: DumpKeyTrust,
  failures: FailureSink,
): void {
  const { signingSince } = keys;
  for (const cp of checkpoints) {
    const chainKey = checkpointChainKeyOf(cp);
    const label = chainLabel(chainKey);
    const entry = chain[cp.chain_position - 1];
    if (!entry) {
      failures.push({
        code: 'CHECKPOINT_ROW_MISSING',
        message: `${label}: checkpoint at position ${cp.chain_position} has no matching audit_vault row (chain length ${chain.length})`,
        scopeId: chainKey,
        position: cp.chain_position,
      });
      continue;
    }
    if (entry.payload_hash !== cp.payload_hash) {
      failures.push({
        code: 'CHECKPOINT_HASH_MISMATCH',
        message: `${label} pos ${cp.chain_position}: checkpoint payload_hash does not match audit_vault row`,
        scopeId: chainKey,
        position: cp.chain_position,
      });
      continue;
    }

    // Engine mirror of `checkpoint_claim_mismatch`, after the row and hash
    // cross-checks and before anything about the key, as the engine orders it.
    const vaultClaim = claimDisagreement(cp.cose_sign1, (c) => [
      ['position', c.position, cp.chain_position],
      ['chain_tip_hash', c.predicate['chain_tip_hash'], `sha256:${cp.payload_hash}`],
      ['subject digest', c.subjectSha256, uuidSubjectDigest(cp.record_id)],
      ['kid', c.kid, cp.signing_key_id ?? UNSIGNED_KID],
    ]);
    if (vaultClaim !== null) {
      failures.push({
        code: 'CHECKPOINT_CLAIM_MISMATCH',
        message: `${label} pos ${cp.chain_position}: checkpoint claim does not match its row: ${vaultClaim}`,
        scopeId: chainKey,
        position: cp.chain_position,
      });
      continue;
    }

    // Only null/undefined means unsigned; "" must resolve in the registry and
    // fail as a missing key rather than silently skip the signature check.
    if (cp.signing_key_id == null) {
      // Engine mirror of `checkpoint_unsigned`. Checked after the row and hash
      // cross-checks, as the engine orders it, so a truncated or diverged
      // chain is still reported under its own code.
      if (writtenWhileSigning(cp.created_at, signingSince)) {
        failures.push({
          code: 'CHECKPOINT_UNSIGNED',
          message: `${label} pos ${cp.chain_position}: checkpoint has no signing_key_id but was written ${cp.created_at}, at or after the earliest signing key activation ${signingSince}`,
          scopeId: chainKey,
          position: cp.chain_position,
        });
      }
    } else {
      const key = signingKeyFor(
        keys.registry,
        cp.signing_key_id,
        'CHECKPOINT_KEY_UNANCHORED',
        `${label} pos ${cp.chain_position}`,
        'checkpoint signing_key_id',
      );
      if ('code' in key) {
        failures.push({ ...key, scopeId: chainKey, position: cp.chain_position, signingKeyId: cp.signing_key_id });
        continue;
      }
      const coseSign1Bytes = Buffer.from(cp.cose_sign1, 'base64');
      const outcome = verifyCoseSign1(coseSign1Bytes, key.spkiBase64);
      // Fail closed on ANY non-ok outcome. 'unsigned' (an all-zero signature
      // on a checkpoint that CLAIMS a signing key) is tampering, not benign:
      // the engine never writes a signing_key_id it did not sign with. An
      // unsupported key algorithm is an upgrade signal, never a pass.
      if (outcome !== 'ok') {
        failures.push({
          code:
            outcome === 'unsupported-key-algorithm'
              ? 'CHAIN_UNSUPPORTED_ALGORITHM'
              : 'CHECKPOINT_SIGNATURE_INVALID',
          message:
            outcome === 'unsupported-key-algorithm'
              ? `${label} pos ${cp.chain_position}: this checkpoint's signature could NOT BE CHECKED. Its signing key ${cp.signing_key_id} ${describeUnsupportedAlgorithm(key.spkiBase64)}`
              : `${label} pos ${cp.chain_position}: checkpoint COSE_Sign1 signature does not verify (${outcome})`,
          scopeId: chainKey,
          position: cp.chain_position,
          signingKeyId: cp.signing_key_id,
        });
      }
    }
  }
}

/**
 * Walk every chain in `audit_vault`, verifying and releasing one chain group at
 * a time.
 *
 * Accepts any iterable, so it takes either a materialized array or the
 * `streamVaultEntries` generator. Given the generator, peak memory is one chain
 * group rather than the whole vault, which is what makes a multi-GB dump
 * verifiable at all (verify#14).
 *
 * **Grouping relies on the dump's row order**, which the producer guarantees:
 * `dump-vault.ts` has emitted `ORDER BY record_id, chain_position` since the
 * format existed, so a record's rows are contiguous and a chain is complete the
 * moment a different record_id appears. Schema-event chains (record_id IS NULL)
 * sort together at the end but interleave with each other, so they stay open
 * until EOF; that set is bounded by schema-registration volume, not by vault
 * size. A chain_key that reappears after its group was closed means the file is
 * not in producer order, and the walk refuses rather than verifying a partial
 * chain and reporting clean.
 */
export function verifyVaultChains(
  entries: Iterable<VaultEntryDump>,
  checkpoints: readonly VaultCheckpointDump[],
  keys: DumpKeyTrust,
  options: VaultChainOptions = {},
): VaultChainsReport {
  const failures = new FailureSink();
  const { registry: keyRegistry, signingSince } = keys;
  // Caller keys first, then the cert keys each clean chain signs. A chain can
  // only use keys harvested from chains closed before it; the producer sorts
  // the platform-ops chain (the all-zero record id) first, so on a dump in
  // producer order every record chain sees every cert key. Out of order, a
  // signature simply goes unchecked, never misjudged.
  const agentKeys = new Map<string, string>(
    options.agentKeys !== undefined ? buildAgentKeyRegistry(options.agentKeys) : [],
  );
  let certKeysFromChain = 0;
  // Each input-gated check is reported `applied` once it ran on any chain, so
  // "not checked anywhere" never reads as "passed".
  const optionalChecks: Record<OptionalCheck, CheckApplicability> = {
    payload_binding: 'skipped_no_input',
    oidc_actor: 'skipped_no_input',
    actor_attribution: 'skipped_no_input',
    key_temporal: 'skipped_no_input',
    agent_signature: 'skipped_no_input',
    key_anchoring: keys.report.status === 'walked' ? 'applied' : 'skipped_no_input',
  };
  const agentSignatures = { present: 0, verified: 0 };

  const checkpointsByChain = new Map<string, VaultCheckpointDump[]>();
  for (const cp of checkpoints) {
    const key = checkpointChainKeyOf(cp);
    const list = checkpointsByChain.get(key);
    if (list) list.push(cp);
    else checkpointsByChain.set(key, [cp]);
  }

  const open = new Map<string, VaultEntryDump[]>();
  const closed = new Set<string>();
  let entryCount = 0;
  let chainCount = 0;

  const report = (recordCount: number): VaultChainsReport => ({
    // Includes per-record chains AND per-enterprise schema-event chains
    // (different shapes, same chain trust model). The `recordCount` name is
    // preserved for back-compat with the report consumer.
    recordCount,
    entryCount,
    checkpointCount: checkpoints.length,
    failures: failures.listed,
    failureCount: failures.count,
    optionalChecks,
    agentSignatures,
    certKeysFromChain,
  });

  const closeChain = (chainKey: string): void => {
    const chain = open.get(chainKey);
    if (!chain) return;
    open.delete(chainKey);
    closed.add(chainKey);
    chainCount++;
    chain.sort((a, b) => a.chain_position - b.chain_position);
    const normalized = chain.map((e) => toNormalizedEntry(chainKey, e));
    // `signingSince` is passed rather than left for the core to derive from
    // `keyRegistry`, so it is the same instant the checkpoint pass uses.
    const result = verifyChain(normalized, keyRegistry, { agentKeys, signingSince });
    for (const check of Object.keys(optionalChecks) as OptionalCheck[]) {
      if (result.optionalChecks[check] === 'applied') optionalChecks[check] = 'applied';
    }
    agentSignatures.present += result.agentSignatures.present;
    agentSignatures.verified += result.agentSignatures.verified;
    const failuresBefore = failures.count;
    collectChainFailures(chainKey, result, failures);
    verifyChainCheckpoints(chain, checkpointsByChain.get(chainKey) ?? [], keys, failures);
    checkpointsByChain.delete(chainKey);
    if (result.valid && failures.count === failuresBefore) {
      certKeysFromChain += harvestCertKeys(chain, result, agentKeys);
    }
  };

  // `undefined` means "no row seen yet"; `null` is a real value (schema chains).
  let previousRecordId: string | null | undefined;

  for (const e of entries) {
    entryCount++;

    // Format gate: format 2.0 requires the canonical COSE_Sign1 envelope on
    // every vault row. A row lacking it is a pre-cutover shape, so fail closed
    // rather than parse best-effort. Stops the walk: one such row means the
    // whole dump came from a pre-cutover engine.
    if (!e.cose_sign1) {
      failures.push({
        code: 'UNSUPPORTED_FORMAT',
        message: `audit_vault row ${e.id} lacks cose_sign1, a pre-2.0 dump shape. This verifier reads exportFormatVersion 2.0 / RFC8949-CDE; re-export from a current AGLedger instance.`,
        scopeId: e.record_id ?? undefined,
        position: e.chain_position,
      });
      return report(0);
    }

    if (previousRecordId !== undefined && previousRecordId !== null && e.record_id !== previousRecordId) {
      closeChain(previousRecordId);
    }
    previousRecordId = e.record_id;

    const chainKey = chainKeyOf(e);
    if (closed.has(chainKey)) {
      failures.push({
        code: 'UNSUPPORTED_FORMAT',
        message: `audit_vault is not in producer order: rows for chain ${chainKey} reappear after the chain was closed (row ${e.id}, position ${e.chain_position}). Chains must be contiguous, as emitted by the shipped dump tool; re-export rather than reordering the file.`,
        scopeId: e.record_id ?? undefined,
        position: e.chain_position,
      });
      return report(chainCount);
    }
    const chain = open.get(chainKey);
    if (chain) chain.push(e);
    else open.set(chainKey, [e]);
  }

  // Empty-vault fail-closed: a dump with zero vault entries must NOT verify
  // clean. (verifyChain returns CHAIN_EMPTY per chain group; this guards the
  // dump level where there are no groups to walk at all.)
  if (entryCount === 0) {
    failures.push({
      code: 'CHAIN_EMPTY',
      message: 'audit_vault contains zero entries, an empty or truncated vault. Refusing to report clean.',
    });
    return report(0);
  }

  for (const chainKey of [...open.keys()]) {
    closeChain(chainKey);
  }

  // Anything left anchors a chain the dump does not contain at all. Reported
  // with the same code as a short chain, since both mean the anchor outlived
  // its rows.
  for (const orphaned of checkpointsByChain.values()) {
    verifyChainCheckpoints([], orphaned, keys, failures);
  }

  return report(chainCount);
}

function groupByOrg<T extends { org_id: string }>(rows: readonly T[]): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const r of rows) {
    const list = map.get(r.org_id);
    if (list) list.push(r);
    else map.set(r.org_id, [r]);
  }
  return map;
}

function detectCheckpointForks(
  checkpoints: readonly OrgAdminReadsCheckpointDump[],
  failures: FailureSink,
): void {
  const byKey = new Map<string, OrgAdminReadsCheckpointDump>();
  for (const cp of checkpoints) {
    const key = `${cp.org_id}:${cp.tree_size}`;
    const prior = byKey.get(key);
    if (prior && prior.root_hash !== cp.root_hash) {
      failures.push({
        code: 'TENANT_CHECKPOINT_FORK',
        message: `Org ${cp.org_id}: two checkpoints at tree_size ${cp.tree_size} carry different root_hash (${prior.id} vs ${cp.id}): engine fork or key compromise`,
        scopeId: cp.org_id,
        treeSize: cp.tree_size,
      });
    } else if (!prior) {
      byKey.set(key, cp);
    }
  }
}

/**
 * Grade one read-log leaf's signature the way the engine does, after its index
 * and hash have been checked. Returns the failure, or null when the leaf holds
 * up. `mustSign.signedBefore` is set by any leaf that names a real key,
 * whatever its own verdict, as the engine's walk does.
 */
function checkLeafSignature(
  orgId: string,
  leaf: OrgAdminReadDump,
  coseSign1Bytes: Buffer,
  registry: KeyRegistry,
  mustSign: { signedBefore: boolean; signingSince: string | null },
): Failure | null {
  const at = `Org ${orgId} leaf ${leaf.leaf_index}`;
  const parts = decodeCoseSign1(coseSign1Bytes);
  const kid = parts ? extractKid(parts.protectedBstr) : null;
  if (kid === null) {
    return {
      code: 'TENANT_READ_SIGNATURE_INVALID',
      message: `${at}: cose_sign1 ${parts ? 'carries no kid' : 'does not decode as a COSE_Sign1 envelope'}, so no signature can be attributed to it`,
      scopeId: orgId,
      leafIndex: leaf.leaf_index,
    };
  }
  if (kid === UNSIGNED_KID) {
    // Engine mirror of `leaf_signature_missing`: unsigned is reduced coverage
    // only before the install began signing and before any signed leaf in
    // this org's log.
    let why: string | null = null;
    if (mustSign.signedBefore) {
      why = 'follows a signed leaf in the same org log';
    } else if (writtenWhileSigning(leaf.read_at, mustSign.signingSince)) {
      why = `was written ${leaf.read_at}, at or after the earliest signing key activation ${mustSign.signingSince}`;
    }
    return why === null
      ? null
      : {
          code: 'TENANT_READ_LEAF_UNSIGNED',
          message: `${at}: leaf is unsigned (kid ${UNSIGNED_KID}) but ${why}`,
          scopeId: orgId,
          leafIndex: leaf.leaf_index,
        };
  }
  mustSign.signedBefore = true;
  const key = signingKeyFor(registry, kid, 'TENANT_READ_KEY_UNANCHORED', at, 'leaf kid');
  if ('code' in key) return { ...key, scopeId: orgId, leafIndex: leaf.leaf_index, signingKeyId: kid };
  const outcome = verifyCoseSign1(coseSign1Bytes, key.spkiBase64);
  // Fail closed on ANY non-ok outcome; an all-zero signature under a real kid
  // ('unsigned') is a wiped signature, as the engine grades it.
  if (outcome === 'ok') return null;
  return {
    code: outcome === 'unsupported-key-algorithm' ? 'CHAIN_UNSUPPORTED_ALGORITHM' : 'TENANT_READ_SIGNATURE_INVALID',
    message:
      outcome === 'unsupported-key-algorithm'
        ? `${at}: this leaf's signature could NOT BE CHECKED. Its signing key ${kid} ${describeUnsupportedAlgorithm(key.spkiBase64)}`
        : `${at}: COSE_Sign1 signature does not verify (${outcome})`,
    scopeId: orgId,
    leafIndex: leaf.leaf_index,
    signingKeyId: kid,
  };
}

function verifyOneOrgAdminReadsLog(
  orgId: string,
  leaves: OrgAdminReadDump[],
  checkpoints: readonly OrgAdminReadsCheckpointDump[],
  keys: DumpKeyTrust,
  failures: FailureSink,
): void {
  const { registry, signingSince } = keys;
  leaves.sort((a, b) => a.leaf_index - b.leaf_index);
  const mustSign = { signedBefore: false, signingSince };

  // One finding per org, the first met in leaf order, then the walk stops
  // before the checkpoints: the engine reports the read log the same way.
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i];
    if (!leaf) continue;
    if (leaf.leaf_index !== i) {
      failures.push({
        code: 'TENANT_READ_LEAF_INDEX_GAP',
        message: `Org ${orgId}: expected leaf_index ${i}, got ${leaf.leaf_index} (id ${leaf.id})`,
        scopeId: orgId,
        leafIndex: leaf.leaf_index,
      });
      return;
    }
    // leaf_hash is the RFC 9162 leaf hash of the envelope bytes.
    const coseSign1Bytes = Buffer.from(leaf.cose_sign1, 'base64');
    const recomputed = orgReadLeafHash(coseSign1Bytes);
    if (recomputed !== leaf.leaf_hash) {
      failures.push({
        code: 'TENANT_READ_LEAF_HASH_MISMATCH',
        message: `Org ${orgId} leaf ${leaf.leaf_index}: the RFC 9162 leaf hash of cose_sign1, sha256(0x00 || bytes), does not match stored leaf_hash`,
        scopeId: orgId,
        leafIndex: leaf.leaf_index,
      });
      return;
    }
    // Engine mirror of `leaf_claim_mismatch`: the claim is what links each
    // leaf to the one before it and to the record it says was read.
    const leafClaim = claimDisagreement(leaf.cose_sign1, (c) => [
      ['position', c.position, i + 1],
      ['previous_hash', c.previousHash, i === 0 ? null : leaves[i - 1]!.leaf_hash],
      ['record_id', c.predicate['record_id'], leaf.record_id],
      ['subject digest', c.subjectSha256, uuidSubjectDigest(leaf.record_id)],
    ]);
    if (leafClaim !== null) {
      failures.push({
        code: 'TENANT_READ_CLAIM_MISMATCH',
        message: `Org ${orgId} leaf ${leaf.leaf_index}: leaf claim does not match its row: ${leafClaim}`,
        scopeId: orgId,
        leafIndex: leaf.leaf_index,
      });
      return;
    }
    const signatureFailure = checkLeafSignature(orgId, leaf, coseSign1Bytes, registry, mustSign);
    if (signatureFailure) {
      failures.push(signatureFailure);
      return;
    }
  }

  const leafHashes = leaves.map((l) => l.leaf_hash);

  for (const cp of checkpoints) {
    if (cp.tree_size > leafHashes.length) {
      failures.push({
        code: 'TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH',
        message: `Org ${orgId}: checkpoint ${cp.id} signs tree_size ${cp.tree_size} but dump contains only ${leafHashes.length} leaves`,
        scopeId: orgId,
        treeSize: cp.tree_size,
      });
      continue;
    }
    // Every leaf hash has been recomputed above, so a null root cannot occur
    // here; it is compared, and fails, like any other wrong root.
    const root = orgReadMerkleRoot(leafHashes.slice(0, cp.tree_size));
    if (root !== cp.root_hash) {
      failures.push({
        code: 'TENANT_CHECKPOINT_ROOT_MISMATCH',
        message: `Org ${orgId}: checkpoint ${cp.id} root_hash ${cp.root_hash.slice(0, 16)} does not match the recomputed RFC 9162 root ${root?.slice(0, 16) ?? '(none)'}`,
        scopeId: orgId,
        treeSize: cp.tree_size,
      });
      continue;
    }

    // Engine mirror of the read log's `checkpoint_claim_mismatch`, after the
    // leaf-count and root cross-checks and before anything about the key.
    const headClaim = claimDisagreement(cp.cose_sign1, (c) => [
      ['position', c.position, cp.tree_size],
      ['chain_tip_hash', c.predicate['chain_tip_hash'], `sha256:${cp.root_hash}`],
      ['count', c.predicate['count'], cp.tree_size],
      ['subject digest', c.subjectSha256, cp.root_hash],
      ['kid', c.kid, cp.signing_key_id ?? UNSIGNED_KID],
    ]);
    if (headClaim !== null) {
      failures.push({
        code: 'TENANT_CHECKPOINT_CLAIM_MISMATCH',
        message: `Org ${orgId}: checkpoint ${cp.id} claim does not match its row: ${headClaim}`,
        scopeId: orgId,
        treeSize: cp.tree_size,
      });
      continue;
    }

    // Only null/undefined means unsigned; "" must resolve in the registry and
    // fail as a missing key rather than silently skip the signature check.
    if (cp.signing_key_id == null) {
      // Engine mirror of the read log's `checkpoint_unsigned`, checked after
      // the leaf-count and root cross-checks as the engine orders it.
      if (writtenWhileSigning(cp.checkpoint_at, signingSince)) {
        failures.push({
          code: 'TENANT_CHECKPOINT_UNSIGNED',
          message: `Org ${orgId}: checkpoint ${cp.id} has no signing_key_id but was written ${cp.checkpoint_at}, at or after the earliest signing key activation ${signingSince}`,
          scopeId: orgId,
          treeSize: cp.tree_size,
        });
      }
    } else {
      const key = signingKeyFor(
        registry,
        cp.signing_key_id,
        'TENANT_CHECKPOINT_KEY_UNANCHORED',
        `Org ${orgId}: checkpoint ${cp.id}`,
        'signing_key_id',
      );
      if ('code' in key) {
        failures.push({ ...key, scopeId: orgId, treeSize: cp.tree_size, signingKeyId: cp.signing_key_id });
        continue;
      }
      const coseSign1Bytes = Buffer.from(cp.cose_sign1, 'base64');
      const outcome = verifyCoseSign1(coseSign1Bytes, key.spkiBase64);
      // Fail closed on ANY non-ok outcome; see the vault-checkpoint site.
      if (outcome !== 'ok') {
        failures.push({
          code:
            outcome === 'unsupported-key-algorithm'
              ? 'CHAIN_UNSUPPORTED_ALGORITHM'
              : 'TENANT_CHECKPOINT_SIGNATURE_INVALID',
          message:
            outcome === 'unsupported-key-algorithm'
              ? `Org ${orgId}: checkpoint ${cp.id}'s signature could NOT BE CHECKED. Its signing key ${cp.signing_key_id} ${describeUnsupportedAlgorithm(key.spkiBase64)}`
              : `Org ${orgId}: checkpoint ${cp.id} COSE_Sign1 signature does not verify (${outcome})`,
          scopeId: orgId,
          treeSize: cp.tree_size,
          signingKeyId: cp.signing_key_id,
        });
      }
    }
  }
}

export function verifyOrgAdminReadsChains(
  reads: readonly OrgAdminReadDump[],
  checkpoints: readonly OrgAdminReadsCheckpointDump[],
  keys: DumpKeyTrust,
): TenantAdminReadsReport {
  const failures = new FailureSink();
  const leavesByOrg = groupByOrg(reads);
  const checkpointsByOrg = groupByOrg(checkpoints);

  detectCheckpointForks(checkpoints, failures);

  // Walk every org that has either leaves OR checkpoints; a checkpoint for an
  // empty leaf set would otherwise slip through silently.
  const orgIds = new Set<string>([...leavesByOrg.keys(), ...checkpointsByOrg.keys()]);
  for (const orgId of orgIds) {
    verifyOneOrgAdminReadsLog(
      orgId,
      leavesByOrg.get(orgId) ?? [],
      checkpointsByOrg.get(orgId) ?? [],
      keys,
      failures,
    );
  }

  // Witness cosignatures are reported, not verified; the engine cannot verify
  // customer-chosen witness keys because their algorithm is untyped.
  const witnessCosignedCheckpoints = checkpoints
    .filter(
      (cp): cp is OrgAdminReadsCheckpointDump & { witness_key_id: string } =>
        cp.witness_signature !== null && cp.witness_key_id !== null,
    )
    .map((cp) => ({ checkpointId: cp.id, witnessKeyId: cp.witness_key_id }));

  return {
    orgCount: orgIds.size,
    leafCount: reads.length,
    checkpointCount: checkpoints.length,
    witnessCosignedCheckpoints,
    failures: failures.listed,
    failureCount: failures.count,
  };
}

/**
 * Combine the two halves and the key walk into the report shape, including
 * the verdict. Shared with the streaming directory entry point in
 * `verify-dir.ts`. A key-statement finding fails the dump like any other; with
 * no anchors and nothing failed the dump passes with the verdict `unanchored`.
 */
export function assembleReport(
  vault: VaultChainsReport,
  orgAdminReads: TenantAdminReadsReport,
  keys: DumpKeyTrust,
): VerifyReport {
  const failed = vault.failureCount > 0 || orgAdminReads.failureCount > 0 || keys.report.findings.length > 0;
  const verdict = failed ? 'failed' : keys.report.status === 'no_anchor' ? 'unanchored' : 'trusted';
  return {
    ok: !failed,
    verdict,
    keyTrust: keys.report,
    vault,
    orgAdminReads,
  };
}

export function verifyDump(dump: Dump, options: VerifyDumpOptions = {}): VerifyReport {
  const keys = walkDumpKeys(dump.signingKeys, dump.keyStatements, options);
  return assembleReport(
    verifyVaultChains(dump.vaultEntries, dump.vaultCheckpoints, keys, options),
    verifyOrgAdminReadsChains(dump.orgAdminReads, dump.orgAdminReadsCheckpoints, keys),
    keys,
  );
}
