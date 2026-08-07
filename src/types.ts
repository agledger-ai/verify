/**
 * Wire shapes for the offline dump format.
 *
 * Each NDJSON file in a dump directory contains one row per line, where each
 * row is a JSON object matching one of the types below. Numbers that are
 * BIGINT in the database (`chain_position`, `tree_size`, `leaf_index`) are
 * serialized as JS numbers because we are far below 2^53; the dump tool is
 * responsible for narrowing.
 *
 * Timestamps are always ISO-8601 strings.
 *
 * **Format version: 2.0 (post COSE_Sign1 cutover, #482).** Pre-2.0 dumps
 * carried `canonical_payload`, `hash_alg`, `signature`, `signature_alg`
 * fields. Post-2.0, those are replaced by a single `cose_sign1` field
 * carrying the base64-encoded canonical COSE_Sign1 envelope (RFC 9052) over
 * an in-toto v1 Statement payload — the chain trust root. A vault entry that
 * lacks `cose_sign1` is a pre-2.0 shape this verifier refuses to parse
 * best-effort (UNSUPPORTED_FORMAT).
 */
import type { FailureCode } from '@agledger/verify-core';

export type { FailureCode };

/** One line of audit_vault.ndjson. */
export interface VaultEntryDump {
  id: string;
  /**
   * Null for schema-event entries (SCHEMA_REGISTERED / SCHEMA_IMPORTED /
   * SCHEMA_DIGEST_MISMATCH) — those write to a per-enterprise chain keyed
   * by `payload.orgId`, not by record_id. Non-null for every other
   * entry type.
   */
  record_id: string | null;
  /**
   * Explicit chain identity emitted by the dump tool. Equals `record_id` for
   * per-record chains; `schema:${orgId ?? '__platform__'}` for schema-
   * event chains. Optional for backward compatibility with dumps produced
   * before v0.23.2 — older dumps lack `chain_key` and the verifier falls back
   * to reconstructing it from `record_id` + `payload.orgId`.
   */
  chain_key?: string;
  entry_type: string;
  /** Denormalized JSONB payload — convenience view, NOT the signed canonical
   *  form. The signed canonical form is `cose_sign1`. */
  payload: Record<string, unknown>;
  /** sha256 of the cose_sign1 envelope bytes. Chain linkage value. */
  payload_hash: string;
  previous_hash: string | null;
  chain_position: number;
  /** Base64-encoded canonical COSE_Sign1 (RFC 9052 §4.4, tag 18) envelope.
   *  REQUIRED in format 2.0. A row missing it is a pre-cutover shape and is
   *  rejected with UNSUPPORTED_FORMAT rather than parsed best-effort. */
  cose_sign1: string;
  signing_key_id: string | null;
  actor_key_id: string;
  actor_role: string;
  actor_owner_id: string;
  /** OIDC issuer URI when the request authenticated via an admin OIDC bearer
   *  (#550). NULL on API-key paths + every pre-#550 dump. Paired with
   *  `actor_oidc_sub` + `actor_oidc_synthesized` at the DB layer via
   *  `chk_audit_vault_actor_oidc_synthesized_paired`. Optional in the dump
   *  JSON for back-compat: dumps produced before #550 omit the columns. */
  actor_oidc_iss?: string | null;
  actor_oidc_sub?: string | null;
  /** TRUE iff the engine itself populated the column pair AND wrote the
   *  same identity into the signed `predicate.on_behalf_of.oidc` (#555).
   *  Drives the row-vs-signed cross-check (CHAIN_OIDC_ACTOR_MISMATCH) — when
   *  TRUE the verifier requires row columns to equal the signed predicate,
   *  so column-DELETION tamper (DBA NULLs the columns on a synthesized row)
   *  surfaces as drift. FALSE on API-key paths and on caller-supplied RFC
   *  8693 delegation. Optional in the dump JSON for back-compat: dumps
   *  produced before #555 lack the field and the verifier falls back to the
   *  older column-nullness guard. */
  actor_oidc_synthesized?: boolean;
  created_at: string;
}

/** One line of vault_checkpoints.ndjson. */
export interface VaultCheckpointDump {
  id?: string;
  /**
   * The engine requires a non-null uuid here even for chains whose rows carry
   * no record id, so a schema chain's checkpoint holds a *derived UUIDv8* hash
   * of the org id. That value matches no `audit_vault` row by inspection, which
   * is why the join must go through `chain_key` and not this column.
   */
  record_id: string;
  /**
   * Explicit chain identity, matching the `chain_key` on the covered
   * `audit_vault` rows. Equals `record_id` for per-record and platform-ops
   * chains; `schema:${orgId ?? '__platform__'}` for schema chains. Optional:
   * dumps produced before the producer emitted it fall back to `record_id`,
   * which is correct for every chain except schema chains (agents#103).
   */
  chain_key?: string;
  chain_position: number;
  payload_hash: string;
  /** Base64-encoded canonical COSE_Sign1 envelope. The signature is inside. */
  cose_sign1: string;
  signing_key_id: string | null;
  created_at?: string;
}

/** One line of vault_signing_keys.ndjson. */
export interface SigningKeyDump {
  key_id: string;
  /** Base64 SPKI DER. */
  public_key: string;
  algorithm: string;
  status: 'active' | 'retired';
  /** Temporal-validity window. Fed into verifyChain for CHAIN_KEY_EXPIRED. */
  activated_at?: string;
  retired_at?: string | null;
  retired_by?: string | null;
}

/** One line of org_admin_reads.ndjson. */
export interface OrgAdminReadDump {
  id: string;
  org_id: string;
  caller_key_id: string;
  record_id: string;
  filter_applied: string;
  read_context: string;
  export_batch_id: string | null;
  read_at: string;
  leaf_index: number;
  leaf_hash: string;
  /** Base64-encoded canonical COSE_Sign1 envelope (org-read claim). */
  cose_sign1: string;
}

/** One line of org_admin_reads_checkpoints.ndjson. */
export interface OrgAdminReadsCheckpointDump {
  id: string;
  org_id: string;
  tree_size: number;
  root_hash: string;
  checkpoint_at: string;
  log_id: string;
  /** Base64-encoded canonical COSE_Sign1 envelope (vault-checkpoint claim
   *  over the Merkle root). */
  cose_sign1: string;
  signing_key_id: string | null;
  witness_signature: string | null;
  witness_key_id: string | null;
  witness_cosigned_at: string | null;
}

/** Full loaded dump. */
export interface Dump {
  vaultEntries: VaultEntryDump[];
  vaultCheckpoints: VaultCheckpointDump[];
  signingKeys: SigningKeyDump[];
  orgAdminReads: OrgAdminReadDump[];
  orgAdminReadsCheckpoints: OrgAdminReadsCheckpointDump[];
}

export interface Failure {
  code: FailureCode;
  message: string;
  /** RecordRow id for vault failures, org id for org-reads failures. */
  scopeId?: string;
  position?: number;
  leafIndex?: number;
  treeSize?: number;
  signingKeyId?: string;
}

/**
 * `failures` is CAPPED at MAX_REPORTED_FAILURES; `failureCount` is the true
 * total. A systemic problem on a large vault (a mishandled key rotation, a
 * truncated table) produces one failure per entry, and a 545k-row vault would
 * otherwise emit hundreds of megabytes of identical lines. Test the verdict
 * with `failureCount`, not `failures.length`.
 */
export interface VaultChainsReport {
  recordCount: number;
  entryCount: number;
  checkpointCount: number;
  /** Capped sample, oldest first. See MAX_REPORTED_FAILURES. */
  failures: Failure[];
  /** Total failures found, including any beyond the cap. */
  failureCount: number;
}

export interface TenantAdminReadsReport {
  orgCount: number;
  leafCount: number;
  checkpointCount: number;
  witnessCosignedCheckpoints: Array<{ checkpointId: string; witnessKeyId: string }>;
  /** Capped sample, oldest first. See MAX_REPORTED_FAILURES. */
  failures: Failure[];
  /** Total failures found, including any beyond the cap. */
  failureCount: number;
}

export interface VerifyReport {
  ok: boolean;
  vault: VaultChainsReport;
  orgAdminReads: TenantAdminReadsReport;
}
