import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import { decodeCoseSign1, merkleRoot, sha256Hex } from '@agledger/verify-core';
import { loadDump } from '../src/loader.js';
import { verifyDump, verifyOrgAdminReadsChains } from '../src/dump-verifier.js';
import { EXIT_VERIFICATION_FAILED, runCli } from '../src/cli.js';
import type { Dump, Failure, FailureCode, OrgAdminReadDump, VerifyReport } from '../src/types.js';

/**
 * The engine's rule for unsigned rows, applied to a dump: an unsigned chain
 * entry, vault checkpoint, read-log leaf or read-log checkpoint is a break
 * when it is written at or after the earliest `activated_at` in the key
 * registry (retired keys included), and an unsigned entry or leaf is also a
 * break after a signed one in its chain or log. Anything else is reduced
 * coverage.
 *
 * Every case is a mutation of a real corpus dump (`dump/valid`: three record
 * chains, three signed vault checkpoints, two signed read-log leaves under a
 * signed tree head, one key activated before all of it).
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const VALID = join(HERE, '..', 'testdata', 'conformance', 'dump', 'valid');
const UNSIGNED_KID = '0000000000000000';

function validDump(): Dump {
  return loadDump(VALID);
}

function codes(report: VerifyReport): FailureCode[] {
  return [...report.vault.failures, ...report.orgAdminReads.failures].map((f) => f.code);
}

function only(report: VerifyReport): Failure {
  const all = [...report.vault.failures, ...report.orgAdminReads.failures];
  expect(all, JSON.stringify(all)).toHaveLength(1);
  return all[0]!;
}

function shiftMs(iso: string, ms: number): string {
  return new Date(Date.parse(iso) + ms).toISOString();
}

/** The key registry's one activation instant. */
function activation(dump: Dump): string {
  const at = dump.signingKeys[0]?.activated_at;
  if (!at) throw new Error('dump/valid must carry an activated_at');
  return at;
}

/** The record chain in dump/valid with more than one entry, in position order. */
function longChain(dump: Dump): Dump['vaultEntries'] {
  const byChain = new Map<string, Dump['vaultEntries']>();
  for (const e of dump.vaultEntries) {
    const list = byChain.get(e.chain_key!) ?? [];
    list.push(e);
    byChain.set(e.chain_key!, list);
  }
  const chain = [...byChain.values()].find((c) => c.length > 1);
  if (!chain) throw new Error('dump/valid must carry a multi-entry chain');
  return chain.sort((a, b) => a.chain_position - b.chain_position);
}

/**
 * Re-encode a real envelope as the engine writes an unsigned one: the kid is
 * the eight-zero-byte sentinel and the signature slot is zeroed. Protected
 * header otherwise unchanged, so every chain claim still holds.
 */
function asUnsignedEnvelope(coseSign1B64: string, kidHex = UNSIGNED_KID, zeroSignature = true): string {
  const parts = decodeCoseSign1(Buffer.from(coseSign1B64, 'base64'));
  if (!parts) throw new Error('corpus envelope must decode');
  const header = cborDecode(parts.protectedBstr, { useMaps: true }) as Map<number, unknown>;
  header.set(4, Buffer.from(kidHex, 'hex'));
  const protectedBstr = cborEncode(header, rfc8949EncodeOptions);
  const signature = zeroSignature ? new Uint8Array(parts.signature.length) : parts.signature;
  const inner = cborEncode([protectedBstr, new Map(), parts.payloadBstr, signature], rfc8949EncodeOptions);
  return Buffer.concat([Buffer.from([0xd2]), inner]).toString('base64');
}

/**
 * Replace a leaf's envelope and restamp leaf_hash, the way a writer holding no
 * key would append it, then re-root the tree head over the new leaves so the
 * Merkle cross-check still holds. The tree head keeps its (now stale)
 * signature, so tests that reach it make it unsigned too.
 */
function replaceLeaf(dump: Dump, index: number, coseSign1: string): OrgAdminReadDump {
  const leaf = dump.orgAdminReads[index]!;
  leaf.cose_sign1 = coseSign1;
  leaf.leaf_hash = sha256Hex(Buffer.from(coseSign1, 'base64'));
  for (const cp of dump.orgAdminReadsCheckpoints) {
    cp.root_hash = merkleRoot(
      dump.orgAdminReads.filter((l) => l.org_id === cp.org_id).slice(0, cp.tree_size).map((l) => l.leaf_hash),
    );
  }
  return leaf;
}

/** Make every read-log tree head unsigned and written before `before`. */
function unsignTreeHeads(dump: Dump, before: string): void {
  for (const cp of dump.orgAdminReadsCheckpoints) {
    cp.signing_key_id = null;
    cp.checkpoint_at = shiftMs(before, -1);
  }
}

describe('baseline', () => {
  it('dump/valid verifies clean and every read-log leaf signature is checked', () => {
    const report = verifyDump(validDump());
    expect(report.ok, JSON.stringify(codes(report))).toBe(true);
    expect(report.orgAdminReads.leafCount).toBe(2);
  });
});

describe('audit_vault chain entries: CHAIN_ENTRY_UNSIGNED', () => {
  it('an unsigned entry after a signed one fails, with no activation time anywhere', () => {
    const dump = validDump();
    // Only the signed-before half of the rule can fire.
    for (const k of dump.signingKeys) delete k.activated_at;
    const chain = longChain(dump);
    chain[1]!.signing_key_id = null;
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'CHAIN_ENTRY_UNSIGNED', position: 2, scopeId: chain[1]!.chain_key });
    expect(failure.message).toContain('follows a signed entry');
  });

  it('an unsigned tip after signed entries fails, the shape a keyless writer leaves', () => {
    const dump = validDump();
    for (const k of dump.signingKeys) delete k.activated_at;
    const chain = longChain(dump);
    chain[chain.length - 1]!.signing_key_id = null;
    expect(only(verifyDump(dump))).toMatchObject({ code: 'CHAIN_ENTRY_UNSIGNED', position: chain.length });
  });

  it('an unsigned first entry written after the earliest activation fails', () => {
    const dump = validDump();
    const chain = longChain(dump);
    for (const e of chain) e.signing_key_id = null;
    const failures = verifyDump(dump).vault.failures;
    // Each entry is graded on its own write time, so every one of them fails.
    expect(failures.map((f) => [f.code, f.position])).toEqual(
      chain.map((e) => ['CHAIN_ENTRY_UNSIGNED', e.chain_position]),
    );
    expect(failures[0]!.message).toContain(activation(dump));
  });

  it('counts a retired key: activation still marks when the install began signing', () => {
    const dump = validDump();
    const key = dump.signingKeys[0]!;
    key.status = 'retired';
    key.retired_at = shiftMs(activation(dump), 1);
    // Keep only the chain under test, all of it unsigned, so the retired key
    // signs nothing that could fail CHAIN_KEY_EXPIRED.
    const chain = longChain(dump);
    for (const e of chain) e.signing_key_id = null;
    dump.vaultEntries = chain;
    dump.vaultCheckpoints = [];
    dump.orgAdminReads = [];
    dump.orgAdminReadsCheckpoints = [];
    const report = verifyDump(dump);
    expect(report.vault.failures.map((f) => f.code)).toEqual(chain.map(() => 'CHAIN_ENTRY_UNSIGNED'));
    expect(report.vault.failures[0]).toMatchObject({ position: 1 });
  });

  it('an all-unsigned chain written before the first key activation is reduced coverage, not a break', () => {
    const dump = validDump();
    const chain = longChain(dump);
    for (const e of chain) e.signing_key_id = null;
    dump.vaultEntries = chain;
    dump.vaultCheckpoints = [];
    dump.orgAdminReads = [];
    dump.orgAdminReadsCheckpoints = [];
    const last = chain[chain.length - 1]!.created_at;
    dump.signingKeys[0]!.activated_at = shiftMs(last, 1);
    const report = verifyDump(dump);
    expect(report.ok, JSON.stringify(codes(report))).toBe(true);

    // At the activation instant itself it is a break: the window is inclusive.
    dump.signingKeys[0]!.activated_at = last;
    expect(only(verifyDump(dump))).toMatchObject({ code: 'CHAIN_ENTRY_UNSIGNED', position: chain.length });
  });

  it('an install with no key at all still verifies an all-unsigned vault', () => {
    const dump = validDump();
    for (const e of dump.vaultEntries) e.signing_key_id = null;
    dump.signingKeys = [];
    dump.vaultCheckpoints = [];
    dump.orgAdminReads = [];
    dump.orgAdminReadsCheckpoints = [];
    const report = verifyDump(dump);
    expect(report.ok, JSON.stringify(codes(report))).toBe(true);
  });

  it('a tampered hash on an unsigned entry is still reported under its own code', () => {
    const dump = validDump();
    const chain = longChain(dump);
    chain[1]!.signing_key_id = null;
    chain[1]!.payload_hash = 'f'.repeat(64);
    expect(codes(verifyDump(dump))[0]).toBe('CHAIN_HASH_MISMATCH');
  });
});

describe('vault_checkpoints: CHECKPOINT_UNSIGNED', () => {
  it('an unsigned checkpoint written after the earliest activation fails', () => {
    const dump = validDump();
    const cp = dump.vaultCheckpoints[0]!;
    cp.signing_key_id = null;
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'CHECKPOINT_UNSIGNED', position: cp.chain_position, scopeId: cp.chain_key });
    expect(failure.message).toContain(activation(dump));
  });

  it('an unsigned checkpoint written before the earliest activation is not a break, and one at it is', () => {
    const dump = validDump();
    const cp = dump.vaultCheckpoints[0]!;
    cp.signing_key_id = null;
    cp.created_at = shiftMs(activation(dump), -1);
    const report = verifyDump(dump);
    expect(report.ok, JSON.stringify(codes(report))).toBe(true);

    cp.created_at = activation(dump);
    expect(only(verifyDump(dump)).code).toBe('CHECKPOINT_UNSIGNED');
  });

  it('an unsigned checkpoint with no write time cannot be placed and stays what it was', () => {
    const dump = validDump();
    const cp = dump.vaultCheckpoints[0]!;
    cp.signing_key_id = null;
    delete cp.created_at;
    expect(verifyDump(dump).ok).toBe(true);
  });

  it('a diverged or orphaned unsigned checkpoint keeps its own code', () => {
    const dump = validDump();
    const [diverged, orphaned] = dump.vaultCheckpoints;
    diverged!.signing_key_id = null;
    diverged!.payload_hash = 'e'.repeat(64);
    orphaned!.signing_key_id = null;
    dump.vaultEntries = dump.vaultEntries.filter((e) => e.chain_key !== orphaned!.chain_key);
    expect(codes(verifyDump(dump)).sort()).toEqual(['CHECKPOINT_HASH_MISMATCH', 'CHECKPOINT_ROW_MISSING']);
  });
});

describe('org_admin_reads leaves: TENANT_READ_LEAF_UNSIGNED', () => {
  it('an unsigned leaf after a signed leaf fails, with no activation time anywhere', () => {
    const dump = validDump();
    for (const k of dump.signingKeys) delete k.activated_at;
    const leaf = replaceLeaf(dump, 1, asUnsignedEnvelope(dump.orgAdminReads[1]!.cose_sign1));
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'TENANT_READ_LEAF_UNSIGNED', leafIndex: 1, scopeId: leaf.org_id });
    expect(failure.message).toContain('follows a signed leaf');
  });

  it('an unsigned first leaf read after the earliest activation fails', () => {
    const dump = validDump();
    replaceLeaf(dump, 0, asUnsignedEnvelope(dump.orgAdminReads[0]!.cose_sign1));
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'TENANT_READ_LEAF_UNSIGNED', leafIndex: 0 });
    expect(failure.message).toContain(activation(dump));
  });

  it('counts a retired key when placing a leaf', () => {
    const dump = validDump();
    dump.signingKeys[0]!.status = 'retired';
    dump.signingKeys[0]!.retired_at = shiftMs(activation(dump), 1);
    replaceLeaf(dump, 0, asUnsignedEnvelope(dump.orgAdminReads[0]!.cose_sign1));
    const report = verifyOrgAdminReadsChains(dump.orgAdminReads, dump.orgAdminReadsCheckpoints, dump.signingKeys);
    expect(report.failures.map((f) => f.code)).toEqual(['TENANT_READ_LEAF_UNSIGNED']);
  });

  it('an all-unsigned log read before the first key activation is reduced coverage, and a leaf at it is a break', () => {
    const dump = validDump();
    const at = shiftMs(dump.orgAdminReads[1]!.read_at, 1);
    dump.signingKeys[0]!.activated_at = at;
    replaceLeaf(dump, 0, asUnsignedEnvelope(dump.orgAdminReads[0]!.cose_sign1));
    replaceLeaf(dump, 1, asUnsignedEnvelope(dump.orgAdminReads[1]!.cose_sign1));
    unsignTreeHeads(dump, at);
    const verify = () =>
      verifyOrgAdminReadsChains(dump.orgAdminReads, dump.orgAdminReadsCheckpoints, dump.signingKeys);
    expect(verify().failures).toEqual([]);

    dump.signingKeys[0]!.activated_at = dump.orgAdminReads[1]!.read_at;
    unsignTreeHeads(dump, dump.orgAdminReads[1]!.read_at);
    expect(verify().failures).toMatchObject([{ code: 'TENANT_READ_LEAF_UNSIGNED', leafIndex: 1 }]);
  });

  it('an unsigned leaf with a rewritten hash reports the hash, and an index gap still comes first', () => {
    const dump = validDump();
    replaceLeaf(dump, 0, asUnsignedEnvelope(dump.orgAdminReads[0]!.cose_sign1));
    dump.orgAdminReads[0]!.leaf_hash = 'd'.repeat(64);
    expect(codes(verifyDump(dump))).toEqual(['TENANT_READ_LEAF_HASH_MISMATCH']);

    const gapped = validDump();
    replaceLeaf(gapped, 1, asUnsignedEnvelope(gapped.orgAdminReads[1]!.cose_sign1));
    gapped.orgAdminReads[1]!.leaf_index = 2;
    expect(codes(verifyDump(gapped))).toEqual(['TENANT_READ_LEAF_INDEX_GAP']);
  });
});

describe('org_admin_reads leaves: the signature a real kid claims', () => {
  it('a zeroed signature under a real kid is TENANT_READ_SIGNATURE_INVALID, never unsigned', () => {
    const dump = validDump();
    const kid = dump.signingKeys[0]!.key_id;
    replaceLeaf(dump, 1, asUnsignedEnvelope(dump.orgAdminReads[1]!.cose_sign1, kid));
    expect(only(verifyDump(dump))).toMatchObject({ code: 'TENANT_READ_SIGNATURE_INVALID', leafIndex: 1 });
  });

  it('a kid the registry does not hold is CHAIN_SIGNATURE_MISSING_KEY', () => {
    const dump = validDump();
    replaceLeaf(dump, 1, asUnsignedEnvelope(dump.orgAdminReads[1]!.cose_sign1, 'ab'.repeat(8), false));
    expect(only(verifyDump(dump))).toMatchObject({
      code: 'CHAIN_SIGNATURE_MISSING_KEY',
      leafIndex: 1,
      signingKeyId: 'ab'.repeat(8),
    });
  });

  it('a leaf restamped over altered envelope bytes fails its signature', () => {
    const dump = validDump();
    const bytes = Buffer.from(dump.orgAdminReads[0]!.cose_sign1, 'base64');
    bytes[bytes.length - 1] = (bytes[bytes.length - 1]! + 1) % 256;
    replaceLeaf(dump, 0, bytes.toString('base64'));
    expect(only(verifyDump(dump))).toMatchObject({ code: 'TENANT_READ_SIGNATURE_INVALID', leafIndex: 0 });
  });

  it('a leaf whose bytes are not a COSE_Sign1 envelope is TENANT_READ_SIGNATURE_INVALID', () => {
    const dump = validDump();
    replaceLeaf(dump, 0, Buffer.from('not an envelope').toString('base64'));
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'TENANT_READ_SIGNATURE_INVALID', leafIndex: 0 });
    expect(failure.message).toContain('does not decode');
  });
});

describe('org_admin_reads_checkpoints: TENANT_CHECKPOINT_UNSIGNED', () => {
  it('an unsigned tree head written after the earliest activation fails', () => {
    const dump = validDump();
    const cp = dump.orgAdminReadsCheckpoints[0]!;
    cp.signing_key_id = null;
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'TENANT_CHECKPOINT_UNSIGNED', scopeId: cp.org_id, treeSize: cp.tree_size });
    expect(failure.message).toContain(activation(dump));
  });

  it('an unsigned tree head written before the earliest activation is not a break, and one at it is', () => {
    const dump = validDump();
    const cp = dump.orgAdminReadsCheckpoints[0]!;
    cp.signing_key_id = null;
    cp.checkpoint_at = shiftMs(activation(dump), -1);
    expect(verifyDump(dump).ok).toBe(true);

    cp.checkpoint_at = activation(dump);
    expect(only(verifyDump(dump)).code).toBe('TENANT_CHECKPOINT_UNSIGNED');
  });

  it('an unsigned tree head over the wrong root reports the root', () => {
    const dump = validDump();
    const cp = dump.orgAdminReadsCheckpoints[0]!;
    cp.signing_key_id = null;
    cp.root_hash = 'c'.repeat(64);
    expect(codes(verifyDump(dump))).toEqual(['TENANT_CHECKPOINT_ROOT_MISMATCH']);
  });
});

describe('CLI', () => {
  it('exits 1 and names each unsigned finding on a dump directory', () => {
    const dump = validDump();
    longChain(dump)[1]!.signing_key_id = null;
    dump.vaultCheckpoints[0]!.signing_key_id = null;
    dump.orgAdminReadsCheckpoints[0]!.signing_key_id = null;
    const dir = mkdtempSync(join(tmpdir(), 'agledger-verify-unsigned-'));
    try {
      const write = (name: string, rows: readonly unknown[]) =>
        writeFileSync(join(dir, name), rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''));
      write('audit_vault.ndjson', dump.vaultEntries);
      write('vault_checkpoints.ndjson', dump.vaultCheckpoints);
      write('vault_signing_keys.ndjson', dump.signingKeys);
      write('org_admin_reads.ndjson', dump.orgAdminReads);
      write('org_admin_reads_checkpoints.ndjson', dump.orgAdminReadsCheckpoints);
      const result = runCli([dir]);
      expect(result.exitCode).toBe(EXIT_VERIFICATION_FAILED);
      for (const code of ['CHAIN_ENTRY_UNSIGNED', 'CHECKPOINT_UNSIGNED', 'TENANT_CHECKPOINT_UNSIGNED']) {
        expect(result.stdout).toContain(`[${code}]`);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
