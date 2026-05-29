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
 * temporal key-validity (CHAIN_KEY_EXPIRED) all come from the core for free.
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

function buildVaultKeyRegistry(keys: readonly SigningKeyDump[]): KeyRegistry {
  const verificationKeys: VerificationKey[] = keys.map((k) => ({
    keyId: k.key_id,
    spkiBase64: k.public_key,
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
 * Group entries by their chain identity + sort by chain_position. Two chain
 * shapes exist in `audit_vault`:
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
function groupByChain(entries: readonly VaultEntryDump[]): Map<string, VaultEntryDump[]> {
  const byChain = new Map<string, VaultEntryDump[]>();
  for (const e of entries) {
    const key =
      e.chain_key ??
      (e.record_id !== null
        ? e.record_id
        : `schema:${(e.payload?.['orgId'] as string | undefined) ?? '__platform__'}`);
    const list = byChain.get(key);
    if (list) list.push(e);
    else byChain.set(key, [e]);
  }
  for (const list of byChain.values()) {
    list.sort((a, b) => a.chain_position - b.chain_position);
  }
  return byChain;
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
function collectChainFailures(scopeId: string, result: ChainResult, failures: Failure[]): void {
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
 * Cross-check checkpoints against the live chain. vault_checkpoints survives
 * audit_vault TRUNCATE — a chain shorter than (or hash-mismatched with) its
 * anchor is evidence of out-of-band tampering. Dump-structural; kept local.
 */
function verifyVaultCheckpoints(
  byChain: Map<string, VaultEntryDump[]>,
  checkpoints: readonly VaultCheckpointDump[],
  keys: Map<string, SigningKeyDump>,
  failures: Failure[],
): void {
  for (const cp of checkpoints) {
    const chain = byChain.get(cp.record_id) ?? [];
    const entry = chain[cp.chain_position - 1];
    if (!entry) {
      failures.push({
        code: 'CHECKPOINT_ROW_MISSING',
        message: `RecordRow ${cp.record_id}: checkpoint at position ${cp.chain_position} has no matching audit_vault row (chain length ${chain.length})`,
        scopeId: cp.record_id,
        position: cp.chain_position,
      });
      continue;
    }
    if (entry.payload_hash !== cp.payload_hash) {
      failures.push({
        code: 'CHECKPOINT_HASH_MISMATCH',
        message: `RecordRow ${cp.record_id} pos ${cp.chain_position}: checkpoint payload_hash does not match audit_vault row`,
        scopeId: cp.record_id,
        position: cp.chain_position,
      });
      continue;
    }

    if (cp.signing_key_id) {
      const key = keys.get(cp.signing_key_id);
      if (!key) {
        failures.push({
          code: 'CHAIN_SIGNATURE_MISSING_KEY',
          message: `RecordRow ${cp.record_id} pos ${cp.chain_position}: checkpoint signing_key_id "${cp.signing_key_id}" not in dumped key registry`,
          scopeId: cp.record_id,
          position: cp.chain_position,
          signingKeyId: cp.signing_key_id,
        });
      } else {
        const coseSign1Bytes = Buffer.from(cp.cose_sign1, 'base64');
        const outcome = verifyCoseSign1(coseSign1Bytes, key.public_key);
        if (outcome === 'invalid' || outcome === 'decode-fail') {
          failures.push({
            code: 'CHECKPOINT_SIGNATURE_INVALID',
            message: `RecordRow ${cp.record_id} pos ${cp.chain_position}: checkpoint COSE_Sign1 signature does not verify`,
            scopeId: cp.record_id,
            position: cp.chain_position,
            signingKeyId: cp.signing_key_id,
          });
        }
      }
    }
  }
}

export function verifyVaultChains(
  entries: readonly VaultEntryDump[],
  checkpoints: readonly VaultCheckpointDump[],
  signingKeys: readonly SigningKeyDump[],
): VaultChainsReport {
  const failures: Failure[] = [];

  // Empty-vault fail-closed: a dump with zero vault entries must NOT verify
  // clean. (verifyChain returns CHAIN_EMPTY per chain group; this guards the
  // dump level where there are no groups to walk at all.)
  if (entries.length === 0) {
    failures.push({
      code: 'CHAIN_EMPTY',
      message: 'audit_vault contains zero entries — empty or truncated vault, refusing to report clean.',
    });
    return {
      recordCount: 0,
      entryCount: 0,
      checkpointCount: checkpoints.length,
      failures,
    };
  }

  // Format gate: format 2.0 requires the canonical COSE_Sign1 envelope on every
  // vault row. A row lacking it is a pre-cutover shape — fail closed rather than
  // parse best-effort.
  const preCutover = entries.filter((e) => !e.cose_sign1);
  if (preCutover.length > 0) {
    const first = preCutover[0]!;
    failures.push({
      code: 'UNSUPPORTED_FORMAT',
      message: `audit_vault row ${first.id} lacks cose_sign1 — pre-2.0 dump shape. This verifier reads exportFormatVersion 2.0 / RFC8949-CDE; re-export from a current AGLedger instance.`,
      scopeId: first.record_id ?? undefined,
      position: first.chain_position,
    });
    return {
      recordCount: 0,
      entryCount: entries.length,
      checkpointCount: checkpoints.length,
      failures,
    };
  }

  const keyRegistry = buildVaultKeyRegistry(signingKeys);
  const keyIndex = indexKeys(signingKeys);
  const byChain = groupByChain(entries);

  for (const [chainKey, chain] of byChain) {
    const normalized = chain.map((e) => toNormalizedEntry(chainKey, e));
    const result = verifyChain(normalized, keyRegistry, {});
    collectChainFailures(chainKey, result, failures);
  }
  verifyVaultCheckpoints(byChain, checkpoints, keyIndex, failures);

  return {
    // Includes per-record chains AND per-enterprise schema-event chains
    // (different shapes, same chain trust model). The `recordCount` name is
    // preserved for back-compat with the report consumer.
    recordCount: byChain.size,
    entryCount: entries.length,
    checkpointCount: checkpoints.length,
    failures,
  };
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
  failures: Failure[],
): void {
  const byKey = new Map<string, OrgAdminReadsCheckpointDump>();
  for (const cp of checkpoints) {
    const key = `${cp.org_id}:${cp.tree_size}`;
    const prior = byKey.get(key);
    if (prior && prior.root_hash !== cp.root_hash) {
      failures.push({
        code: 'TENANT_CHECKPOINT_FORK',
        message: `Org ${cp.org_id}: two checkpoints at tree_size ${cp.tree_size} carry different root_hash (${prior.id} vs ${cp.id}) — engine fork or key compromise`,
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
  failures: Failure[],
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

    if (cp.signing_key_id) {
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
        if (outcome === 'invalid' || outcome === 'decode-fail') {
          failures.push({
            code: 'TENANT_CHECKPOINT_SIGNATURE_INVALID',
            message: `Org ${orgId}: checkpoint ${cp.id} COSE_Sign1 signature does not verify`,
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
  const failures: Failure[] = [];
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
    failures,
  };
}

export function verifyDump(dump: Dump): VerifyReport {
  const vault = verifyVaultChains(dump.vaultEntries, dump.vaultCheckpoints, dump.signingKeys);
  const orgAdminReads = verifyOrgAdminReadsChains(
    dump.orgAdminReads,
    dump.orgAdminReadsCheckpoints,
    dump.signingKeys,
  );
  return {
    ok: vault.failures.length === 0 && orgAdminReads.failures.length === 0,
    vault,
    orgAdminReads,
  };
}
