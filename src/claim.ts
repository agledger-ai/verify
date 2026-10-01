/**
 * The signed claim inside a checkpoint or read-log envelope, decoded the way
 * the engine decodes it (`decodeCoseSign1ToClaim` in the engine's COSE_Sign1
 * encoder) so a dump is held to the same claim checks the engine's own scan
 * applies. An envelope the engine would not decode as a claim decodes to null
 * here, and the caller reports that as a claim mismatch, as the engine does.
 *
 * Only what those checks read is returned: the chain position and previous
 * hash, the signed kid, the first subject's sha256 digest, and the predicate.
 */
import { decode as cborDecode } from 'cborg';
import { decodeCoseSign1, sha256Hex } from '@agledger/verify-core';

const COSE_HEADER_KID = 4;
const COSE_HEADER_CWT_CLAIMS = 15;
const CWT_LABEL_ISS = 1;
const CWT_LABEL_SUB = 2;
const CWT_LABEL_IAT = 6;
const AGLEDGER_LABEL_CHAIN = -65537;
const AGLEDGER_LABEL_ACTOR = -65539;
const CHAIN_SUBLABEL_POSITION = 1;
const CHAIN_SUBLABEL_PREVIOUS_HASH = 2;
const ACTOR_SUBLABEL_KEY_ID = 1;
const ACTOR_SUBLABEL_ROLE = 2;
const ACTOR_SUBLABEL_OWNER_ID = 3;
const PREDICATE_TYPE = /^https:\/\/agledger\.ai\/predicates\/(.+)\/v1$/;

export interface SignedClaim {
  position: number;
  previousHash: string | null;
  /** The protected-header kid, lowercase hex. */
  kid: string;
  /** `subject[0].digest.sha256`, lowercase hex, or undefined when absent. */
  subjectSha256: string | undefined;
  predicate: Record<string, unknown>;
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

/** Decode an envelope's signed claim, or null where the engine's decoder returns null. */
export function decodeSignedClaim(coseSign1: Uint8Array): SignedClaim | null {
  const parts = decodeCoseSign1(coseSign1);
  if (!parts) return null;
  try {
    const ph = cborDecode(parts.protectedBstr, { useMaps: true }) as Map<number, unknown>;
    const payload = cborDecode(parts.payloadBstr, { useMaps: false }) as Record<string, unknown>;
    const cwt = ph.get(COSE_HEADER_CWT_CLAIMS);
    const chain = ph.get(AGLEDGER_LABEL_CHAIN);
    if (!(cwt instanceof Map) || !(chain instanceof Map)) return null;
    const actor = cwt.get(AGLEDGER_LABEL_ACTOR);
    if (!(actor instanceof Map)) return null;
    const kid = ph.get(COSE_HEADER_KID);
    if (!(kid instanceof Uint8Array)) return null;
    const iat = cwt.get(CWT_LABEL_IAT);
    if (typeof cwt.get(CWT_LABEL_ISS) !== 'string' || typeof cwt.get(CWT_LABEL_SUB) !== 'string') return null;
    if (typeof iat !== 'number' && typeof iat !== 'bigint') return null;
    const position = chain.get(CHAIN_SUBLABEL_POSITION);
    if (typeof position !== 'number' && typeof position !== 'bigint') return null;
    const prev = chain.get(CHAIN_SUBLABEL_PREVIOUS_HASH);
    if (prev !== null && !(prev instanceof Uint8Array)) return null;
    if (!(actor.get(ACTOR_SUBLABEL_KEY_ID) instanceof Uint8Array)) return null;
    if (!(actor.get(ACTOR_SUBLABEL_OWNER_ID) instanceof Uint8Array)) return null;
    const role = actor.get(ACTOR_SUBLABEL_ROLE);
    if (role !== 'admin' && role !== 'agent' && role !== 'platform') return null;
    const predicateType = payload['predicateType'];
    if (typeof predicateType !== 'string' || !PREDICATE_TYPE.test(predicateType)) return null;
    const subject = payload['subject'];
    if (!Array.isArray(subject)) return null;
    const first = subject[0] as { digest?: Record<string, unknown> } | undefined;
    const digest = first?.digest?.['sha256'];
    const predicate = payload['predicate'];
    return {
      position: typeof position === 'bigint' ? Number(position) : position,
      previousHash: prev === null ? null : hex(prev),
      kid: hex(kid),
      subjectSha256: digest instanceof Uint8Array ? hex(digest) : undefined,
      predicate: predicate !== null && typeof predicate === 'object' && !Array.isArray(predicate)
        ? (predicate as Record<string, unknown>)
        : {},
    };
  } catch {
    return null;
  }
}

/** sha256 of a UUID's 16 bytes, the digest the engine signs as a record's subject. */
export function uuidSubjectDigest(uuid: unknown): string | null {
  if (typeof uuid !== 'string') return null;
  const h = uuid.replace(/-/g, '').toLowerCase();
  return /^[0-9a-f]{32}$/.test(h) ? sha256Hex(Buffer.from(h, 'hex')) : null;
}
