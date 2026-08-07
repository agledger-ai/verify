/**
 * Pure verification functions over an already-loaded dump. No I/O, no DB, no
 * global state.
 *
 * The per-record (and per-org schema-event) hash-chain walk is delegated
 * wholesale to `@agledger/verify-core`'s `verifyChain` — the single body of
 * logic the SDK /verify subpath, the CLI, and the MCP server all run. Each
 * grouped chain's rows are adapted into the core's `NormalizedEntry` shape,
 * carrying the dump-only inputs the export wire cannot: the binding-integrity
 * payload, the OIDC-actor columns, and the per-entry write time. The signing
 * key registry is built from the dump's `vault_signing_keys` with their
 * temporal windows, so binding-integrity, OIDC-actor cross-check, AND
 * temporal key-validity (CHAIN_KEY_NOT_YET_ACTIVE / CHAIN_KEY_EXPIRED) all come
 * from the core for free.
 *
 * What stays LOCAL to this package is the dump-structural work the core does
 * not model: the vault-checkpoint cross-check against the live chain, and the
 * org_admin_reads Merkle log + signed-tree-head + fork-detection passes. They
 * use verify-core primitives (merkleRoot, verifyCoseSign1, sha256Hex) and emit
 * the canonical CHECKPOINT_* / TENANT_* codes.
 *
 * Fail-closed posture (security review):
 *   - A dump with zero vault entries is CHAIN_EMPTY, never a silent pass.
 *   - A vault entry lacking `cose_sign1` is a pre-2.0 shape -> UNSUPPORTED_FORMAT;
 *     we do not parse it best-effort.
 *   - Temporal key-validity is enforced by feeding each entry's created_at and
 *     each key's activated_at/retired_at into verifyChain.
 */
import {
  buildKeyRegistry,
  describeUnsupportedAlgorithm,
  merkleRoot,
  sha256Hex,
  verifyChain,
  verifyCoseSign1,
  type ChainResult,
  type KeyRegistry,
  type NormalizedEntry,
  type VerificationKey,
} from '@agledger/verify-core';
import type {
  Dump,
  Failure,
  SigningKeyDump,
  OrgAdminReadDump,
  OrgAdminReadsCheckpointDump,
  TenantAdminReadsReport,
  VaultChainsReport,
  VaultCheckpointDump,
  VaultEntryDump,
  VerifyReport,
} from './types.js';

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

function indexKeys(keys: readonly SigningKeyDump[]): Map<string, SigningKeyDump> {
  const map = new Map<string, SigningKeyDump>();
  for (const k of keys) {
    map.set(k.key_id, k);
  }
  return map;
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
 * correct for every chain except schema chains (agents#103).
 */
function checkpointChainKeyOf(cp: VaultCheckpointDump): string {
  return cp.chain_key ?? cp.record_id;
}

/**
 * How a chain is named in failure messages. A per-record chain key IS a record
 * id, so "RecordRow <uuid>" is a lookup an auditor can act on. A schema chain
 * key is not: labelling it that way sent auditors to /v1/records/{id} for a 404
 * (agents#103), so it is named as the chain it actually is.
 */
function chainLabel(chainKey: string): string {
  return chainKey.startsWith('schema:') ? `Chain ${chainKey}` : `RecordRow ${chainKey}`;
}

/** Adapt a dump vault row into the verify-core normalized entry shape, carrying
 *  the dump-only inputs (binding, oidcActor, createdAt). */
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
  };
}

/** Translate a verify-core ChainResult into this package's flat Failure list,
 *  preserving the canonical code + a dump-flavored message. */
function collectChainFailures(scopeId: string, result: ChainResult, failures: FailureSink): void {
  for (const entry of result.entries) {
    if (entry.valid || !entry.failure) continue;
    failures.push({
      code: entry.failure.code,
      message: `RecordRow ${scopeId} pos ${entry.position}: ${entry.failure.detail}`,
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
  keys: Map<string, SigningKeyDump>,
  failures: FailureSink,
): void {
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

    // Only null/undefined means unsigned; "" must resolve in the registry and
    // fail as a missing key rather than silently skip the signature check.
    if (cp.signing_key_id != null) {
      const key = keys.get(cp.signing_key_id);
      if (!key) {
        failures.push({
          code: 'CHAIN_SIGNATURE_MISSING_KEY',
          message: `${label} pos ${cp.chain_position}: checkpoint signing_key_id "${cp.signing_key_id}" not in dumped key registry`,
          scopeId: chainKey,
          position: cp.chain_position,
          signingKeyId: cp.signing_key_id,
        });
      } else {
        const coseSign1Bytes = Buffer.from(cp.cose_sign1, 'base64');
        const outcome = verifyCoseSign1(coseSign1Bytes, key.public_key);
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
                ? `${label} pos ${cp.chain_position}: this checkpoint's signature could NOT BE CHECKED. Its signing key ${cp.signing_key_id} ${describeUnsupportedAlgorithm(key.public_key)}`
                : `${label} pos ${cp.chain_position}: checkpoint COSE_Sign1 signature does not verify (${outcome})`,
            scopeId: chainKey,
            position: cp.chain_position,
            signingKeyId: cp.signing_key_id,
          });
        }
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
  signingKeys: readonly SigningKeyDump[],
): VaultChainsReport {
  const failures = new FailureSink();
  const keyRegistry = buildVaultKeyRegistry(signingKeys);
  const keyIndex = indexKeys(signingKeys);

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
  });

  const closeChain = (chainKey: string): void => {
    const chain = open.get(chainKey);
    if (!chain) return;
    open.delete(chainKey);
    closed.add(chainKey);
    chainCount++;
    chain.sort((a, b) => a.chain_position - b.chain_position);
    const normalized = chain.map((e) => toNormalizedEntry(chainKey, e));
    collectChainFailures(chainKey, verifyChain(normalized, keyRegistry, {}), failures);
    verifyChainCheckpoints(chain, checkpointsByChain.get(chainKey) ?? [], keyIndex, failures);
    checkpointsByChain.delete(chainKey);
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
    verifyChainCheckpoints([], orphaned, keyIndex, failures);
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

function verifyOneOrgAdminReadsLog(
  orgId: string,
  leaves: OrgAdminReadDump[],
  checkpoints: readonly OrgAdminReadsCheckpointDump[],
  keys: Map<string, SigningKeyDump>,
  failures: FailureSink,
): void {
  leaves.sort((a, b) => a.leaf_index - b.leaf_index);

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
    // leaf_hash is sha256(cose_sign1) post-cutover.
    const coseSign1Bytes = Buffer.from(leaf.cose_sign1, 'base64');
    const recomputed = sha256Hex(coseSign1Bytes);
    if (recomputed !== leaf.leaf_hash) {
      failures.push({
        code: 'TENANT_READ_LEAF_HASH_MISMATCH',
        message: `Org ${orgId} leaf ${leaf.leaf_index}: sha256(cose_sign1) does not match stored leaf_hash`,
        scopeId: orgId,
        leafIndex: leaf.leaf_index,
      });
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
    const root = merkleRoot(leafHashes.slice(0, cp.tree_size));
    if (root !== cp.root_hash) {
      failures.push({
        code: 'TENANT_CHECKPOINT_ROOT_MISMATCH',
        message: `Org ${orgId}: checkpoint ${cp.id} root_hash ${cp.root_hash.slice(0, 16)} does not match recomputed root ${root.slice(0, 16)}`,
        scopeId: orgId,
        treeSize: cp.tree_size,
      });
      continue;
    }

    // Only null/undefined means unsigned; "" must resolve in the registry and
    // fail as a missing key rather than silently skip the signature check.
    if (cp.signing_key_id != null) {
      const key = keys.get(cp.signing_key_id);
      if (!key) {
        failures.push({
          code: 'CHAIN_SIGNATURE_MISSING_KEY',
          message: `Org ${orgId}: checkpoint ${cp.id} signing_key_id "${cp.signing_key_id}" not in dumped key registry`,
          scopeId: orgId,
          treeSize: cp.tree_size,
          signingKeyId: cp.signing_key_id,
        });
      } else {
        const coseSign1Bytes = Buffer.from(cp.cose_sign1, 'base64');
        const outcome = verifyCoseSign1(coseSign1Bytes, key.public_key);
        // Fail closed on ANY non-ok outcome; see the vault-checkpoint site.
        if (outcome !== 'ok') {
          failures.push({
            code:
              outcome === 'unsupported-key-algorithm'
                ? 'CHAIN_UNSUPPORTED_ALGORITHM'
                : 'TENANT_CHECKPOINT_SIGNATURE_INVALID',
            message:
              outcome === 'unsupported-key-algorithm'
                ? `Org ${orgId}: checkpoint ${cp.id}'s signature could NOT BE CHECKED. Its signing key ${cp.signing_key_id} ${describeUnsupportedAlgorithm(key.public_key)}`
                : `Org ${orgId}: checkpoint ${cp.id} COSE_Sign1 signature does not verify (${outcome})`,
            scopeId: orgId,
            treeSize: cp.tree_size,
            signingKeyId: cp.signing_key_id,
          });
        }
      }
    }
  }
}

export function verifyOrgAdminReadsChains(
  reads: readonly OrgAdminReadDump[],
  checkpoints: readonly OrgAdminReadsCheckpointDump[],
  signingKeys: readonly SigningKeyDump[],
): TenantAdminReadsReport {
  const failures = new FailureSink();
  const keys = indexKeys(signingKeys);
  const leavesByOrg = groupByOrg(reads);
  const checkpointsByOrg = groupByOrg(checkpoints);

  detectCheckpointForks(checkpoints, failures);

  // Walk every org that has either leaves OR checkpoints — a checkpoint for an
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

  // Witness cosignatures are reported, not verified — the engine cannot verify
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

/** Combine the two halves into the report shape, including the `ok` verdict.
 *  Shared with the streaming directory entry point in `verify-dir.ts`. */
export function assembleReport(
  vault: VaultChainsReport,
  orgAdminReads: TenantAdminReadsReport,
): VerifyReport {
  return {
    ok: vault.failureCount === 0 && orgAdminReads.failureCount === 0,
    vault,
    orgAdminReads,
  };
}

export function verifyDump(dump: Dump): VerifyReport {
  return assembleReport(
    verifyVaultChains(dump.vaultEntries, dump.vaultCheckpoints, dump.signingKeys),
    verifyOrgAdminReadsChains(dump.orgAdminReads, dump.orgAdminReadsCheckpoints, dump.signingKeys),
  );
}
