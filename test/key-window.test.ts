/**
 * Vault checkpoints, read-log leaves and read-log tree heads against the
 * signed window of the key that signed them, and the ones a distrustedKeys
 * entry accounts for. The Server's scan reports the same findings as
 * checkpoint_key_not_yet_active, checkpoint_key_expired,
 * leaf_key_not_yet_active, leaf_key_expired, accounted_checkpoint_only and
 * checkpoint_accounted_run_exceeded, and lists the rows set aside in
 * distrustedCheckpoints and orgAdminReads.distrustedEntries.
 */
import { describe, expect, it } from 'vitest';
import { ACCOUNTED_CHECKPOINT_RUN_CAP, verifyDump } from '../src/dump-verifier.js';
import { formatDumpReportText } from '../src/cli.js';
import type { Dump, FailureCode, VerifyReport } from '../src/types.js';
import {
  buildHappyDump,
  buildKeyStatement,
  buildOrgAdminReadsCheckpoint,
  buildVaultCheckpoint,
  generateKey,
  pinOf,
  signingKeyDump,
  stableUuidFromString,
  type KeyMaterial,
} from './fixtures.js';

const ACTIVATED = '2026-01-01T00:00:00.000000Z';
const RETIRED = '2026-06-01T00:00:00.000000Z';
/** The instant a dated distrust entry gives for the first key. */
const DISTRUSTED_FROM = '2026-03-01T00:00:00Z';

function codes(report: VerifyReport): FailureCode[] {
  return [
    ...report.vault.failures.map((f) => f.code),
    ...report.orgAdminReads.failures.map((f) => f.code),
    ...report.keyTrust.findings.map((f) => f.code),
  ];
}

/**
 * The happy dump, every row signed by `k1` (entries and the vault checkpoint
 * in February, the read log in April), after a rotation: `k1` was active from
 * January and `k2` succeeded it in June, each edge signed.
 */
function rotated(): { dump: Dump; k1: KeyMaterial; k2: KeyMaterial } {
  const { dump, key: k1 } = buildHappyDump();
  const k2 = generateKey();
  dump.signingKeys = [
    signingKeyDump(k1, { activatedAt: '2026-01-01T00:00:00.000Z', retiredAt: '2026-06-01T00:00:00.000Z', status: 'retired' }),
    signingKeyDump(k2, { activatedAt: '2026-06-01T00:00:00.000Z' }),
  ];
  dump.keyStatements = [
    buildKeyStatement('genesis', k1, { signers: [k1], activatedAt: ACTIVATED, createdAt: ACTIVATED }),
    buildKeyStatement('succession', k2, { endorser: k1, signers: [k1, k2], activatedAt: RETIRED, createdAt: RETIRED }),
    buildKeyStatement('closure', k1, { endorser: k2, signers: [k2], activatedAt: ACTIVATED, retiredAt: RETIRED, createdAt: '2026-06-01T00:00:01.000000Z' }),
  ];
  return { dump, k1, k2 };
}

/** Flip a bit of the signature, the last bytes of the envelope. */
function wipeSignature(coseSign1: string): string {
  const bytes = Buffer.from(coseSign1, 'base64');
  bytes[bytes.length - 1]! ^= 0x01;
  return bytes.toString('base64');
}

describe('a row written outside its signing key\'s window', () => {
  it('passes the rotated dump, every row inside the window of the key that signed it', () => {
    const { dump, k2 } = rotated();
    const report = verifyDump(dump, { trustAnchors: [pinOf(k2)] });
    expect(codes(report)).toEqual([]);
    expect(report.verdict).toBe('trusted');
  });

  it.each([
    ['after the retirement', '2026-06-01T00:00:00.001Z', 'KEY_EXPIRED'],
    ['before the activation', '2025-12-31T23:59:59.999Z', 'KEY_NOT_YET_ACTIVE'],
  ] as const)('fails a vault checkpoint, a leaf and a tree head written %s', (_when, at, suffix) => {
    const { dump, k2 } = rotated();
    dump.vaultCheckpoints[0]!.created_at = at;
    const checkpoint = verifyDump(dump, { trustAnchors: [pinOf(k2)] });
    expect(codes(checkpoint)).toEqual([`CHECKPOINT_${suffix}`]);
    expect(checkpoint.vault.failures[0]).toMatchObject({ position: 3, signingKeyId: dump.vaultCheckpoints[0]!.signing_key_id });
    expect(checkpoint.vault.failures[0]!.message).toMatch(/Checkpoint written /);

    const leafDump = rotated();
    leafDump.dump.orgAdminReads[1]!.read_at = at;
    expect(codes(verifyDump(leafDump.dump, { trustAnchors: [pinOf(leafDump.k2)] }))).toEqual([`TENANT_READ_${suffix}`]);

    const headDump = rotated();
    headDump.dump.orgAdminReadsCheckpoints[0]!.checkpoint_at = at;
    expect(codes(verifyDump(headDump.dump, { trustAnchors: [pinOf(headDump.k2)] }))).toEqual([`TENANT_CHECKPOINT_${suffix}`]);
  });

  it('passes a row written exactly at the retirement', () => {
    const { dump, k2 } = rotated();
    dump.vaultCheckpoints[0]!.created_at = '2026-06-01T00:00:00.000Z';
    dump.orgAdminReads[1]!.read_at = '2026-06-01T00:00:00.000Z';
    dump.orgAdminReadsCheckpoints[0]!.checkpoint_at = '2026-06-01T00:00:00.000Z';
    expect(codes(verifyDump(dump, { trustAnchors: [pinOf(k2)] }))).toEqual([]);
  });

  it('reports a signature that does not verify ahead of the window', () => {
    const { dump, k2 } = rotated();
    const cp = dump.vaultCheckpoints[0]!;
    cp.created_at = '2026-07-01T00:00:00.000Z';
    cp.cose_sign1 = wipeSignature(cp.cose_sign1);
    const head = dump.orgAdminReadsCheckpoints[0]!;
    head.checkpoint_at = '2026-07-01T00:00:00.000Z';
    head.cose_sign1 = wipeSignature(head.cose_sign1);
    expect(codes(verifyDump(dump, { trustAnchors: [pinOf(k2)] }))).toEqual(['CHECKPOINT_SIGNATURE_INVALID', 'TENANT_CHECKPOINT_SIGNATURE_INVALID']);
  });

  it('fails closed on a row whose write time cannot be read', () => {
    const { dump, k2 } = rotated();
    (dump.vaultCheckpoints[0] as { created_at: unknown }).created_at = '2026-02-01 06:00:00';
    const report = verifyDump(dump, { trustAnchors: [pinOf(k2)] });
    expect(report.ok).toBe(false);
    expect(report.vault.failures.at(-1)!.message).toMatch(/no parseable write time/);
  });

  it('with no pin, holds a row to the window the registry row lists, as it holds an entry', () => {
    const { dump } = buildHappyDump();
    dump.vaultCheckpoints[0]!.created_at = '2031-01-01T00:00:00.000Z';
    expect(verifyDump(dump).verdict).toBe('unanchored');
    dump.signingKeys[0]!.retired_at = '2030-01-01T00:00:00.000Z';
    expect(codes(verifyDump(dump))).toEqual(['CHECKPOINT_KEY_EXPIRED']);
  });
});

describe('rows a distrustedKeys entry accounts for', () => {
  const options = (k1: KeyMaterial, k2: KeyMaterial) => ({ trustAnchors: [pinOf(k2)], distrustedKeys: [`${pinOf(k1)}@${DISTRUSTED_FROM}`] });

  it('sets aside what the key signed from the distrust instant to its retirement, and verifies what it signed before', () => {
    const { dump, k1, k2 } = rotated();
    const report = verifyDump(dump, options(k1, k2));
    expect(codes(report)).toEqual([]);
    expect(report.ok).toBe(true);
    // February: entries and the vault checkpoint, before the instant.
    expect(report.vault.accountedCount).toBe(0);
    expect(report.vault.accountedCheckpointCount).toBe(0);
    // April: the read log, four leaves and a tree head.
    expect(report.orgAdminReads.accountedCount).toBe(5);
    expect(report.orgAdminReads.accounted.map((a) => `${a.orgId} ${a.kind} ${a.at}`)).toEqual([
      'enterprise-1 leaf 0', 'enterprise-1 leaf 1', 'enterprise-1 leaf 2', 'enterprise-1 checkpoint 3', 'enterprise-2 leaf 0',
    ]);
    expect(report.orgAdminReads.accounted[0]).toMatchObject({ code: 'CHAIN_SIGNED_BY_DISTRUSTED_KEY', keyId: k1.keyId });
    const text = formatDumpReportText(report);
    expect(text).toMatch(/accounted for {4}: 5 \(signed by a distrusted key/);
    expect(text).toContain('Org enterprise-1 tree head at size 3');
  });

  it('lists a vault checkpoint written inside the span, and compares no chain with it', () => {
    const { dump, k1, k2 } = rotated();
    const cp = dump.vaultCheckpoints[0]!;
    cp.created_at = '2026-04-01T00:00:00.000Z';
    // A holder of the leaked key anchors a position the chain never reached.
    const planted = { ...buildVaultCheckpoint('record-bbbb', 999, 'ab'.repeat(32), k1), created_at: '2026-04-02T00:00:00.000Z' };
    dump.vaultCheckpoints.push(planted);
    const report = verifyDump(dump, options(k1, k2));
    expect(codes(report)).toEqual([]);
    expect(report.vault.accountedCheckpoints.map((a) => a.position)).toEqual([3, 999]);
    expect(report.vault.accountedCheckpoints[0]).toMatchObject({ chain: 'record', keyId: k1.keyId, code: 'CHAIN_SIGNED_BY_DISTRUSTED_KEY' });
    expect(formatDumpReportText(report)).toMatch(/checkpoints set aside: 2 /);
  });

  it('compares no root and finds no fork among tree heads set aside', () => {
    const { dump, k1, k2 } = rotated();
    const leaves = dump.orgAdminReads.filter((l) => l.org_id === 'enterprise-1');
    const forged = buildOrgAdminReadsCheckpoint('enterprise-1', [...leaves].reverse(), k1, 3);
    dump.orgAdminReadsCheckpoints.push({ ...forged, id: 'forged' });
    const report = verifyDump(dump, options(k1, k2));
    expect(codes(report)).toEqual([]);
    expect(report.orgAdminReads.accounted.filter((a) => a.kind === 'checkpoint')).toHaveLength(2);
  });

  it('still holds a leaf set aside to its index, hash and claim', () => {
    const { dump, k1, k2 } = rotated();
    dump.orgAdminReads[1]!.leaf_hash = 'cd'.repeat(32);
    expect(codes(verifyDump(dump, options(k1, k2)))).toEqual(['TENANT_READ_LEAF_HASH_MISMATCH']);
  });

  it('sets nothing aside whose signature does not verify under the key', () => {
    const { dump, k1, k2 } = rotated();
    const head = dump.orgAdminReadsCheckpoints[0]!;
    head.cose_sign1 = wipeSignature(head.cose_sign1);
    const report = verifyDump(dump, options(k1, k2));
    expect(codes(report)).toEqual(['TENANT_CHECKPOINT_SIGNATURE_INVALID']);
    expect(report.orgAdminReads.accounted.some((a) => a.kind === 'checkpoint')).toBe(false);
  });

  it('fails what the key signed after a trusted key retired it', () => {
    const { dump, k1, k2 } = rotated();
    dump.vaultCheckpoints[0]!.created_at = '2026-06-02T00:00:00.000Z';
    dump.orgAdminReadsCheckpoints[0]!.checkpoint_at = '2026-06-02T00:00:00.000Z';
    expect(codes(verifyDump(dump, options(k1, k2)))).toEqual(['CHECKPOINT_KEY_EXPIRED', 'TENANT_CHECKPOINT_KEY_EXPIRED']);
  });

  it('sets aside every row of an unanchored distrusted key that a trusted key retired, where it failed each as unanchored', () => {
    // k1 has no statement linking it to the pin; k2, pinned, runs under its
    // own genesis and retired k1 with force.
    const { dump, k1, k2 } = rotated();
    dump.keyStatements = [
      buildKeyStatement('genesis', k1, { signers: [k1], activatedAt: ACTIVATED, createdAt: ACTIVATED }),
      buildKeyStatement('genesis', k2, { signers: [k2], activatedAt: RETIRED, createdAt: RETIRED }),
      buildKeyStatement('closure', k1, { endorser: k2, signers: [k2], activatedAt: ACTIVATED, retiredAt: RETIRED, forced: true, createdAt: '2026-06-01T00:00:01.000000Z' }),
    ];
    const without = verifyDump(dump, { trustAnchors: [pinOf(k2)] });
    // One finding per org log, so the leaf is reported and the walk stops before the tree head.
    expect(codes(without)).toEqual(expect.arrayContaining(['CHAIN_SIGNING_KEY_UNANCHORED', 'CHECKPOINT_KEY_UNANCHORED', 'TENANT_READ_KEY_UNANCHORED']));

    const report = verifyDump(dump, { trustAnchors: [pinOf(k2)], distrustedKeys: [pinOf(k1)] });
    expect(report.vault.failures).toEqual([]);
    expect(report.orgAdminReads.failures).toEqual([]);
    expect(report.vault.accountedCount).toBe(6);
    expect(report.vault.accountedCheckpointCount).toBe(1);
    expect(report.orgAdminReads.accountedCount).toBe(5);
  });
});

describe('a chain left with only checkpoints set aside', () => {
  const options = (k1: KeyMaterial, k2: KeyMaterial) => ({ trustAnchors: [pinOf(k2)], distrustedKeys: [`${pinOf(k1)}@${DISTRUSTED_FROM}`] });
  const uuid = stableUuidFromString('record-bbbb');

  it('fails a chain with no entry whose only checkpoints are set aside', () => {
    const { dump, k1, k2 } = rotated();
    dump.vaultEntries = dump.vaultEntries.filter((e) => e.record_id !== uuid);
    dump.vaultCheckpoints[0]!.created_at = '2026-04-01T00:00:00.000Z';
    const report = verifyDump(dump, options(k1, k2));
    expect(codes(report)).toEqual(['CHECKPOINT_ACCOUNTED_ONLY']);
    expect(report.vault.failures[0]).toMatchObject({ scopeId: uuid, position: 0 });
  });

  it('reports the missing rows instead when one checkpoint of the chain is not set aside', () => {
    const { dump, k1, k2 } = rotated();
    dump.vaultEntries = dump.vaultEntries.filter((e) => e.record_id !== uuid);
    dump.vaultCheckpoints.push({ ...buildVaultCheckpoint('record-bbbb', 2, 'ab'.repeat(32), k1), created_at: '2026-04-01T00:00:00.000Z' });
    expect(codes(verifyDump(dump, options(k1, k2)))).toEqual(['CHECKPOINT_ROW_MISSING']);
  });

  it('fails a run of set-aside checkpoints longer than the walk reads above the newest that is not', () => {
    const run = (length: number): VerifyReport => {
      const { dump, k1, k2 } = rotated();
      for (let i = 0; i < length; i++) {
        dump.vaultCheckpoints.push({ ...buildVaultCheckpoint('record-bbbb', 4 + i, 'ab'.repeat(32), k1), created_at: '2026-04-01T00:00:00.000Z' });
      }
      return verifyDump(dump, options(k1, k2));
    };
    expect(codes(run(ACCOUNTED_CHECKPOINT_RUN_CAP))).toEqual([]);
    const over = run(ACCOUNTED_CHECKPOINT_RUN_CAP + 1);
    expect(codes(over)).toEqual(['CHECKPOINT_ACCOUNTED_RUN_EXCEEDED']);
    expect(over.vault.failures[0]).toMatchObject({ scopeId: uuid, position: 4 });
    expect(over.vault.accountedCheckpointCount).toBe(ACCOUNTED_CHECKPOINT_RUN_CAP + 1);
  });
});
