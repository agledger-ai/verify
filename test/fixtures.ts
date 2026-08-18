/**
 * Build a self-consistent in-memory dump using a minimal local COSE_Sign1
 * producer. Returns a Dump that should pass verification cleanly. Adversarial
 * tests and the conformance generator mutate a clone of this baseline.
 *
 * The producer here mirrors the engine encoder (audit-vault/encoders/
 * cose-sign1.ts): same protected header labels, same CWT layout, same
 * payload-as-in-toto-v1-Statement shape, same RFC 8949 §4.2.1 deterministic
 * encoding via cborg.rfc8949EncodeOptions.
 *
 * Inlined rather than imported to keep the verifier's load-bearing zero-engine-
 * dependency property: the offline auditor works even if the engine is
 * compromised, and these fixtures prove the verifier interoperates with a
 * conforming producer that isn't engine code.
 */
import { createPrivateKey, generateKeyPairSync, hash, sign as nodeSign } from 'node:crypto';
import { encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import type { Dump, SigningKeyDump } from '../src/types.js';

export interface KeyMaterial {
  privateKeyDerB64: string;
  publicKeyDerB64: string;
  keyId: string;
}

export function generateKey(seedSuffix = ''): KeyMaterial {
  const pair = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding: { type: 'spki', format: 'der' },
  });
  const privateKeyDerB64 = Buffer.from(pair.privateKey).toString('base64');
  const publicKeyDerB64 = Buffer.from(pair.publicKey).toString('base64');
  const keyId = hash('sha256', Buffer.from(publicKeyDerB64, 'base64'), 'hex').slice(0, 16) + seedSuffix;
  return { privateKeyDerB64, publicKeyDerB64, keyId };
}

const COSE_SIGN1_TAG_PREFIX = 0xd2;
const COSE_ALG_EDDSA = -8;
const IN_TOTO_CBOR_CTY = 'application/vnd.in-toto+cbor';
const IN_TOTO_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
const AGLEDGER_LABEL_CHAIN = -65537;
const AGLEDGER_LABEL_ACTOR = -65539;

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`bad hex length: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uuidToBytes(uuid: string): Uint8Array {
  return hexToBytes(uuid.replace(/-/g, ''));
}

interface Actor {
  key_id: string;
  role: 'admin' | 'agent' | 'platform';
  owner_id: string;
}

interface CoseSign1Input {
  kind: 'record-state' | 'org-read' | 'vault-checkpoint';
  kidHex: string;
  iss: string;
  sub: string;
  iat: number;
  actor: Actor;
  chainPosition: number;
  previousHashHex: string | null;
  subject: Array<{ name?: string; digest: { sha256?: string } }>;
  predicate: Record<string, unknown>;
}

function buildProtectedHeader(input: CoseSign1Input): Map<number, unknown> {
  const cwt = new Map<number, unknown>();
  cwt.set(1, input.iss);
  cwt.set(2, input.sub);
  cwt.set(6, input.iat);
  const actorMap = new Map<number, unknown>();
  actorMap.set(1, uuidToBytes(input.actor.key_id));
  actorMap.set(2, input.actor.role);
  actorMap.set(3, uuidToBytes(input.actor.owner_id));
  cwt.set(AGLEDGER_LABEL_ACTOR, actorMap);

  const chain = new Map<number, unknown>();
  chain.set(1, input.chainPosition);
  chain.set(2, input.previousHashHex === null ? null : hexToBytes(input.previousHashHex));

  const ph = new Map<number, unknown>();
  ph.set(1, COSE_ALG_EDDSA);
  ph.set(3, IN_TOTO_CBOR_CTY);
  ph.set(4, hexToBytes(input.kidHex));
  ph.set(15, cwt);
  ph.set(AGLEDGER_LABEL_CHAIN, chain);
  return ph;
}

function buildPayload(input: CoseSign1Input): Record<string, unknown> {
  const subject = input.subject.map((d) => {
    const inner: Record<string, unknown> = {
      digest: Object.fromEntries(
        Object.entries(d.digest)
          .filter(([, v]) => typeof v === 'string')
          .map(([algo, hex]) => [algo, hexToBytes(hex as string)]),
      ),
    };
    if (d.name !== undefined) inner.name = d.name;
    return inner;
  });
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    predicate: input.predicate,
    predicateType: `https://agledger.ai/predicates/${input.kind}/v1`,
    subject,
  };
}

function signEd25519Bytes(privateKeyDerB64: string, input: Uint8Array): Uint8Array {
  const keyObj = createPrivateKey({
    key: Buffer.from(privateKeyDerB64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
  return Uint8Array.from(nodeSign(null, input, keyObj));
}

/** Build a tagged COSE_Sign1 envelope and return both bytes + sha256(envelope). */
export function buildCoseSign1(
  input: CoseSign1Input,
  key: KeyMaterial,
): { bytes: Uint8Array; base64: string; payloadHash: string } {
  const protectedBstr = cborEncode(buildProtectedHeader(input), rfc8949EncodeOptions);
  const payloadBstr = cborEncode(buildPayload(input), rfc8949EncodeOptions);
  const sigStructure: unknown[] = ['Signature1', protectedBstr, new Uint8Array(0), payloadBstr];
  const toBeSigned = cborEncode(sigStructure, rfc8949EncodeOptions);
  const signature = signEd25519Bytes(key.privateKeyDerB64, toBeSigned);
  const coseSign1: unknown[] = [protectedBstr, new Map(), payloadBstr, signature];
  const innerBytes = cborEncode(coseSign1, rfc8949EncodeOptions);
  const bytes = new Uint8Array(1 + innerBytes.length);
  bytes[0] = COSE_SIGN1_TAG_PREFIX;
  bytes.set(innerBytes, 1);
  return {
    bytes,
    base64: Buffer.from(bytes).toString('base64'),
    payloadHash: hash('sha256', bytes, 'hex'),
  };
}

const SHARED_ACTOR: Actor = {
  key_id: '11111111-1111-1111-1111-111111111111',
  role: 'agent',
  owner_id: '22222222-2222-2222-2222-222222222222',
};
const ISS = 'https://api.example.test';

function recordSubjectFor(recordId: string): Array<{ name: string; digest: { sha256: string } }> {
  return [{ name: 'record_id', digest: { sha256: hash('sha256', recordId, 'hex') } }];
}

interface BuildVaultEntryArgs {
  recordId: string;
  position: number;
  previousHash: string | null;
  entryType: string;
  payload: Record<string, unknown>;
  key: KeyMaterial;
  createdAt?: string;
  /** When set, the signed predicate carries on_behalf_of.oidc and the row gets
   *  matching actor_oidc_* columns with actor_oidc_synthesized=true. */
  oidc?: { iss: string; sub: string };
}

export function buildVaultEntry(args: BuildVaultEntryArgs): Dump['vaultEntries'][number] {
  const recordUuid = stableUuidFromString(args.recordId);
  const predicate: Record<string, unknown> = {
    record_id: recordUuid,
    entry_type: args.entryType,
    payload: args.payload,
  };
  if (args.oidc) {
    predicate['on_behalf_of'] = { oidc: { iss: args.oidc.iss, sub: args.oidc.sub } };
  }
  const envelope = buildCoseSign1(
    {
      kind: 'record-state',
      kidHex: args.key.keyId,
      iss: ISS,
      sub: recordUuid,
      iat: 1747574400 + args.position,
      actor: SHARED_ACTOR,
      chainPosition: args.position,
      previousHashHex: args.previousHash,
      subject: recordSubjectFor(args.recordId),
      predicate,
    },
    args.key,
  );
  const row: Dump['vaultEntries'][number] = {
    id: `entry-${args.recordId}-${args.position}`,
    // Match the engine's row shape: record_id is the UUID written into the
    // signed predicate, NOT the synthetic short-key the fixture uses for lookup.
    record_id: recordUuid,
    entry_type: args.entryType,
    payload: args.payload,
    payload_hash: envelope.payloadHash,
    previous_hash: args.previousHash,
    chain_position: args.position,
    cose_sign1: envelope.base64,
    signing_key_id: args.key.keyId,
    actor_key_id: SHARED_ACTOR.key_id,
    actor_role: SHARED_ACTOR.role,
    actor_owner_id: SHARED_ACTOR.owner_id,
    created_at: args.createdAt ?? '2026-02-01T00:00:00.000Z',
  };
  if (args.oidc) {
    row.actor_oidc_iss = args.oidc.iss;
    row.actor_oidc_sub = args.oidc.sub;
    row.actor_oidc_synthesized = true;
  }
  return row;
}

export function buildVaultCheckpoint(
  recordId: string,
  position: number,
  payloadHash: string,
  key: KeyMaterial,
): Dump['vaultCheckpoints'][number] {
  const recordUuid = stableUuidFromString(recordId);
  const envelope = buildCoseSign1(
    {
      kind: 'vault-checkpoint',
      kidHex: key.keyId,
      iss: ISS,
      sub: recordUuid,
      iat: 1747574500,
      actor: SHARED_ACTOR,
      chainPosition: position,
      previousHashHex: null,
      subject: recordSubjectFor(recordId),
      predicate: {
        chain_tip_hash: `sha256:${payloadHash}`,
        range: { start: 1, end: position },
        count: position,
      },
    },
    key,
  );
  return {
    id: `cp-${recordId}-${position}`,
    record_id: recordUuid,
    chain_position: position,
    payload_hash: payloadHash,
    cose_sign1: envelope.base64,
    signing_key_id: key.keyId,
    created_at: '2026-02-01T06:00:00.000Z',
  };
}

interface BuildLeafArgs {
  orgId: string;
  leafIndex: number;
  key: KeyMaterial;
  callerKeyId?: string;
  recordId?: string;
}

export function buildOrgAdminRead(args: BuildLeafArgs): Dump['orgAdminReads'][number] {
  const id = `oar-${args.orgId}-${args.leafIndex}`;
  const recordId = args.recordId ?? `record-${args.leafIndex}`;
  const recordUuid = stableUuidFromString(recordId);
  const callerKeyIdHex = args.callerKeyId ?? '0a'.repeat(8);
  const envelope = buildCoseSign1(
    {
      kind: 'org-read',
      kidHex: args.key.keyId,
      iss: ISS,
      sub: recordUuid,
      iat: 1747574000 + args.leafIndex,
      actor: SHARED_ACTOR,
      chainPosition: args.leafIndex + 1,
      previousHashHex: null,
      subject: recordSubjectFor(recordId),
      predicate: {
        record_id: recordUuid,
        reader_key_id: callerKeyIdHex,
        signed_checkpoint_ref: null,
      },
    },
    args.key,
  );
  return {
    id,
    org_id: args.orgId,
    caller_key_id: callerKeyIdHex,
    record_id: recordId,
    filter_applied: 'org-admin',
    read_context: 'interactive',
    export_batch_id: null,
    read_at: new Date(2026, 3, 25, 12, 0, args.leafIndex).toISOString(),
    leaf_index: args.leafIndex,
    leaf_hash: envelope.payloadHash,
    cose_sign1: envelope.base64,
  };
}

function merkleRootLocal(leaves: readonly string[]): string {
  if (leaves.length === 0) return hash('sha256', '', 'hex');
  let level: string[] = [...leaves];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i] ?? '';
      const right = level[i + 1] ?? left;
      next.push(hash('sha256', left + right, 'hex'));
    }
    level = next;
  }
  return level[0] ?? '';
}

export function buildOrgAdminReadsCheckpoint(
  orgId: string,
  leaves: ReadonlyArray<Dump['orgAdminReads'][number]>,
  key: KeyMaterial,
  treeSize?: number,
): Dump['orgAdminReadsCheckpoints'][number] {
  const size = treeSize ?? leaves.length;
  const slice = leaves.slice(0, size).map((l) => l.leaf_hash);
  const rootHash = merkleRootLocal(slice);
  const envelope = buildCoseSign1(
    {
      kind: 'vault-checkpoint',
      kidHex: key.keyId,
      iss: ISS,
      sub: orgId,
      iat: 1747574999,
      actor: SHARED_ACTOR,
      chainPosition: size > 0 ? size : 1,
      previousHashHex: null,
      subject: [{ name: 'org_id', digest: { sha256: hash('sha256', orgId, 'hex') } }],
      predicate: {
        chain_tip_hash: `sha256:${rootHash}`,
        range: { start: 0, end: size },
        count: size,
      },
    },
    key,
  );
  return {
    id: `oar-cp-${orgId}-${size}`,
    org_id: orgId,
    tree_size: size,
    root_hash: rootHash,
    checkpoint_at: new Date(2026, 3, 25, 18, 0, 0).toISOString(),
    log_id: orgId,
    cose_sign1: envelope.base64,
    signing_key_id: key.keyId,
    witness_signature: null,
    witness_key_id: null,
    witness_cosigned_at: null,
  };
}

export interface HappyDumpResult {
  dump: Dump;
  key: KeyMaterial;
}

/**
 * Two records of three entries each, plus a checkpoint on the second record at
 * position 3. Two orgs in org_admin_reads, one with three leaves and a signed
 * checkpoint, one with no checkpoint yet (matches a fresh org where the 6h
 * sweep hasn't fired).
 */
export function buildHappyDump(): HappyDumpResult {
  const key = generateKey();
  const signingKey: SigningKeyDump = {
    key_id: key.keyId,
    public_key: key.publicKeyDerB64,
    algorithm: 'Ed25519',
    status: 'active',
    activated_at: new Date(2026, 0, 1).toISOString(),
    retired_at: null,
    retired_by: null,
  };

  const m1 = 'record-aaaa';
  const m2 = 'record-bbbb';
  const m1e1 = buildVaultEntry({ recordId: m1, position: 1, previousHash: null, entryType: 'RECORD_CREATED', payload: { kind: 'create', m: m1 }, key });
  const m1e2 = buildVaultEntry({ recordId: m1, position: 2, previousHash: m1e1.payload_hash, entryType: 'RECORD_STATE_CHANGE', payload: { kind: 'transition', m: m1, n: 2 }, key });
  const m1e3 = buildVaultEntry({ recordId: m1, position: 3, previousHash: m1e2.payload_hash, entryType: 'RECORD_STATE_CHANGE', payload: { kind: 'transition', m: m1, n: 3 }, key });
  const m2e1 = buildVaultEntry({ recordId: m2, position: 1, previousHash: null, entryType: 'RECORD_CREATED', payload: { kind: 'create', m: m2 }, key });
  const m2e2 = buildVaultEntry({ recordId: m2, position: 2, previousHash: m2e1.payload_hash, entryType: 'RECORD_STATE_CHANGE', payload: { kind: 'transition', m: m2, n: 2 }, key });
  const m2e3 = buildVaultEntry({ recordId: m2, position: 3, previousHash: m2e2.payload_hash, entryType: 'RECORD_STATE_CHANGE', payload: { kind: 'transition', m: m2, n: 3 }, key });

  const cp = buildVaultCheckpoint(m2, 3, m2e3.payload_hash, key);

  const ent1 = 'enterprise-1';
  const ent2 = 'enterprise-2';
  const leaves1 = [
    buildOrgAdminRead({ orgId: ent1, leafIndex: 0, key }),
    buildOrgAdminRead({ orgId: ent1, leafIndex: 1, key }),
    buildOrgAdminRead({ orgId: ent1, leafIndex: 2, key }),
  ];
  const tarCp1 = buildOrgAdminReadsCheckpoint(ent1, leaves1, key, 3);
  const leaves2 = [buildOrgAdminRead({ orgId: ent2, leafIndex: 0, key })];

  return {
    key,
    dump: {
      vaultEntries: [m1e1, m1e2, m1e3, m2e1, m2e2, m2e3],
      vaultCheckpoints: [cp],
      signingKeys: [signingKey],
      orgAdminReads: [...leaves1, ...leaves2],
      orgAdminReadsCheckpoints: [tarCp1],
    },
  };
}

/** Build a SigningKeyDump from key material, with an optional temporal window. */
export function signingKeyDump(
  key: KeyMaterial,
  window?: { activatedAt?: string; retiredAt?: string | null; status?: 'active' | 'retired' },
): SigningKeyDump {
  return {
    key_id: key.keyId,
    public_key: key.publicKeyDerB64,
    algorithm: 'Ed25519',
    status: window?.status ?? 'active',
    activated_at: window?.activatedAt ?? new Date(2026, 0, 1).toISOString(),
    retired_at: window?.retiredAt ?? null,
    retired_by: null,
  };
}

/** Deep clone a dump so mutations don't bleed across cases. */
export function cloneDump(dump: Dump): Dump {
  return JSON.parse(JSON.stringify(dump)) as Dump;
}

/**
 * Stable UUID derived from an arbitrary string, needed because record_id in
 * the in-toto subject digest and the predicate must be UUID-shaped. We don't
 * lean on randomUUID() because the same string must yield the same UUID across
 * builders (entry vs. checkpoint subject).
 */
export function stableUuidFromString(s: string): string {
  const h = hash('sha256', s, 'hex').slice(0, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}
