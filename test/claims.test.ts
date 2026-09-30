/**
 * The claim checks: each vault checkpoint, read-log leaf and read-log tree head
 * carries a signed claim, and the row beside it must say the same thing, as
 * the engine's scan holds them (`checkpoint_claim_mismatch`,
 * `leaf_claim_mismatch`). Every case tampers a real corpus dump (`dump/valid`)
 * while leaving the hash and root cross-checks intact, which is the gap the
 * claim checks close.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { orgReadMerkleRoot } from '@agledger/verify-core';
import { verifyDump } from '../src/dump-verifier.js';
import { loadDump } from '../src/loader.js';
import type { Dump, Failure, VerifyReport } from '../src/types.js';

const VALID = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'conformance', 'dump', 'valid');

function only(report: VerifyReport): Failure {
  const all = [...report.vault.failures, ...report.orgAdminReads.failures];
  expect(all, JSON.stringify(all)).toHaveLength(1);
  return all[0]!;
}

function valid(): Dump {
  const dump = loadDump(VALID);
  expect(dump.vaultCheckpoints.length).toBeGreaterThanOrEqual(2);
  expect(dump.orgAdminReads).toHaveLength(2);
  expect(dump.orgAdminReadsCheckpoints).toHaveLength(1);
  return dump;
}

describe('vault checkpoints: CHECKPOINT_CLAIM_MISMATCH', () => {
  it('the unmodified dump carries no claim finding', () => {
    expect(verifyDump(valid()).ok).toBe(true);
  });

  it('an envelope moved onto another chain\'s checkpoint row, its columns intact', () => {
    const dump = valid();
    const [a, b] = dump.vaultCheckpoints;
    a!.cose_sign1 = b!.cose_sign1;
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'CHECKPOINT_CLAIM_MISMATCH', scopeId: a!.chain_key, position: a!.chain_position });
    expect(failure.message).toContain('checkpoint claim does not match its row');
  });

  it('a record_id column rewritten under an intact envelope', () => {
    const dump = valid();
    dump.vaultCheckpoints[0]!.record_id = '019a0000-0000-7000-8000-000000000001';
    expect(only(verifyDump(dump))).toMatchObject({ code: 'CHECKPOINT_CLAIM_MISMATCH' });
    expect(only(verifyDump(dump)).message).toContain('subject digest');
  });

  it('a key id column nulled beside a signed envelope is a claim mismatch, not an unsigned checkpoint', () => {
    const dump = valid();
    dump.vaultCheckpoints[0]!.signing_key_id = null;
    const failure = only(verifyDump(dump));
    expect(failure.code).toBe('CHECKPOINT_CLAIM_MISMATCH');
    expect(failure.message).toContain('kid');
  });

  it('bytes that are not an envelope', () => {
    const dump = valid();
    dump.vaultCheckpoints[0]!.cose_sign1 = Buffer.from('not an envelope').toString('base64');
    expect(only(verifyDump(dump)).message).toContain('does not decode as a signed AGLedger claim');
  });

  it('the row and hash cross-checks still come first', () => {
    const dump = valid();
    const [a, b] = dump.vaultCheckpoints;
    a!.cose_sign1 = b!.cose_sign1;
    a!.payload_hash = 'e'.repeat(64);
    expect(only(verifyDump(dump)).code).toBe('CHECKPOINT_HASH_MISMATCH');
  });
});

describe('read-log leaves: TENANT_READ_CLAIM_MISMATCH', () => {
  it('a record_id column rewritten under an intact leaf', () => {
    const dump = valid();
    dump.orgAdminReads[1]!.record_id = '019a0000-0000-7000-8000-000000000002';
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'TENANT_READ_CLAIM_MISMATCH', leafIndex: 1 });
    expect(failure.message).toContain('record_id');
  });

  it('two leaves swapped and renumbered, so every index and hash still holds', () => {
    const dump = valid();
    const [first, second] = dump.orgAdminReads;
    [first!.leaf_index, second!.leaf_index] = [1, 0];
    const cp = dump.orgAdminReadsCheckpoints[0]!;
    cp.root_hash = orgReadMerkleRoot([second!.leaf_hash, first!.leaf_hash])!;
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'TENANT_READ_CLAIM_MISMATCH', leafIndex: 0 });
    expect(failure.message).toContain('position');
  });

  it('the index and hash checks still come first', () => {
    const dump = valid();
    dump.orgAdminReads[1]!.record_id = '019a0000-0000-7000-8000-000000000002';
    dump.orgAdminReads[1]!.leaf_hash = 'a'.repeat(64);
    expect(only(verifyDump(dump)).code).toBe('TENANT_READ_LEAF_HASH_MISMATCH');
  });
});

describe('read-log tree heads: TENANT_CHECKPOINT_CLAIM_MISMATCH', () => {
  it('a tree head cut to a smaller tree_size with its root recomputed to match', () => {
    const dump = valid();
    const cp = dump.orgAdminReadsCheckpoints[0]!;
    cp.tree_size = 1;
    cp.root_hash = orgReadMerkleRoot([dump.orgAdminReads[0]!.leaf_hash])!;
    const failure = only(verifyDump(dump));
    expect(failure).toMatchObject({ code: 'TENANT_CHECKPOINT_CLAIM_MISMATCH', scopeId: cp.org_id, treeSize: 1 });
    expect(failure.message).toContain('position');
  });

  it('a key id column nulled beside a signed tree head', () => {
    const dump = valid();
    dump.orgAdminReadsCheckpoints[0]!.signing_key_id = null;
    const failure = only(verifyDump(dump));
    expect(failure.code).toBe('TENANT_CHECKPOINT_CLAIM_MISMATCH');
    expect(failure.message).toContain('kid');
  });

  it('the root check still comes first', () => {
    const dump = valid();
    const cp = dump.orgAdminReadsCheckpoints[0]!;
    cp.signing_key_id = null;
    cp.root_hash = 'c'.repeat(64);
    expect(only(verifyDump(dump)).code).toBe('TENANT_CHECKPOINT_ROOT_MISMATCH');
  });
});
