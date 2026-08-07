import { describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { verifyDump, verifyOrgAdminReadsChains, verifyVaultChains } from '../src/dump-verifier.js';
import {
  buildHappyDump,
  buildOrgAdminRead,
  buildOrgAdminReadsCheckpoint,
  buildVaultEntry,
  cloneDump,
  generateKey,
  signingKeyDump,
} from './fixtures.js';

/** Flip a byte at the given offset of a base64-encoded byte string. */
function mutateBase64Byte(base64: string, offset: number): string {
  const buf = Buffer.from(base64, 'base64');
  const idx = offset < 0 ? buf.length + offset : offset;
  buf[idx] = (buf[idx]! ^ 0xff) & 0xff;
  return buf.toString('base64');
}

describe('verifyDump — happy path', () => {
  it('reports ok=true and surfaces no failures on a clean dump', () => {
    const { dump } = buildHappyDump();
    const report = verifyDump(dump);
    expect(report.ok).toBe(true);
    expect(report.vault.failures).toEqual([]);
    expect(report.orgAdminReads.failures).toEqual([]);
    expect(report.vault.recordCount).toBe(2);
    expect(report.vault.entryCount).toBe(6);
    expect(report.vault.checkpointCount).toBe(1);
    expect(report.orgAdminReads.orgCount).toBe(2);
    expect(report.orgAdminReads.leafCount).toBe(4);
  });

  it('surfaces witness cosignatures without verifying them', () => {
    const { dump } = buildHappyDump();
    const cp = dump.orgAdminReadsCheckpoints[0];
    expect(cp).toBeDefined();
    if (!cp) return;
    cp.witness_signature = 'aa'.repeat(32);
    cp.witness_key_id = 'witness-key-1';
    cp.witness_cosigned_at = '2026-04-25T19:00:00.000Z';
    const report = verifyDump(dump);
    expect(report.ok).toBe(true);
    expect(report.orgAdminReads.witnessCosignedCheckpoints).toEqual([
      { checkpointId: cp.id, witnessKeyId: 'witness-key-1' },
    ]);
  });
});

describe('verifyVaultChains — fail-closed fixes (security review)', () => {
  it('CHAIN_EMPTY when the vault has zero entries (empty/truncated)', () => {
    const report = verifyVaultChains([], [], []);
    expect(report.failures.some((f) => f.code === 'CHAIN_EMPTY')).toBe(true);
  });

  it('verifyDump does not report ok on an entirely empty dump', () => {
    const report = verifyDump({
      vaultEntries: [],
      vaultCheckpoints: [],
      signingKeys: [],
      orgAdminReads: [],
      orgAdminReadsCheckpoints: [],
    });
    expect(report.ok).toBe(false);
    expect(report.vault.failures.some((f) => f.code === 'CHAIN_EMPTY')).toBe(true);
  });

  it('UNSUPPORTED_FORMAT when a vault row lacks cose_sign1 (pre-2.0 shape)', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    // Strip the canonical envelope to simulate a pre-cutover dump shape.
    (tampered.vaultEntries[0] as { cose_sign1?: string }).cose_sign1 = '';
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'UNSUPPORTED_FORMAT')).toBe(true);
  });

  it('CHAIN_KEY_EXPIRED when an entry is signed outside the key activated..retired window', () => {
    const key = generateKey();
    // Key retired before the entries were written.
    const sk = signingKeyDump(key, {
      activatedAt: '2026-01-01T00:00:00.000Z',
      retiredAt: '2026-01-15T00:00:00.000Z',
      status: 'retired',
    });
    const e1 = buildVaultEntry({
      recordId: 'record-late',
      position: 1,
      previousHash: null,
      entryType: 'RECORD_CREATED',
      payload: { kind: 'create' },
      key,
      createdAt: '2026-03-01T00:00:00.000Z',
    });
    const report = verifyVaultChains([e1], [], [sk]);
    expect(report.failures.some((f) => f.code === 'CHAIN_KEY_EXPIRED')).toBe(true);
  });
});

describe('verifyVaultChains — adversarial cases via verify-core', () => {
  it('CHAIN_HASH_MISMATCH when payload_hash is rewritten', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    const target = tampered.vaultEntries[1]!;
    target.payload_hash = 'ff'.repeat(32);
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHAIN_HASH_MISMATCH')).toBe(true);
  });

  it('CHAIN_LINK_BROKEN when previous_hash is wrong on a later entry', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.vaultEntries[2]!.previous_hash = 'ff'.repeat(32);
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHAIN_LINK_BROKEN')).toBe(true);
  });

  it('CHAIN_GENESIS_INVALID when genesis entry has a non-null previous_hash', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.vaultEntries[0]!.previous_hash = 'aa'.repeat(32);
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHAIN_GENESIS_INVALID')).toBe(true);
  });

  it('CHAIN_POSITION_GAP when an entry is dropped', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.vaultEntries.splice(1, 1);
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHAIN_POSITION_GAP')).toBe(true);
  });

  it('CHAIN_SIGNATURE_INVALID when the signature slot is mutated', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    const target = tampered.vaultEntries[1]!;
    const buf = Buffer.from(target.cose_sign1, 'base64');
    buf[buf.length - 1] = (buf[buf.length - 1]! ^ 0xff) & 0xff;
    target.cose_sign1 = buf.toString('base64');
    target.payload_hash = createHash('sha256').update(buf).digest('hex');
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHAIN_SIGNATURE_INVALID')).toBe(true);
  });

  it('CHAIN_UNSUPPORTED_ALGORITHM says the signature was not checked, never that it failed', () => {
    // An uncheckable checkpoint must not be reported in the language of a
    // failed signature: those lead an auditor to opposite conclusions, and
    // only one of them is grounds for a tamper investigation (agents#113).
    // Driven here by a key type this build cannot compute, which reaches the
    // same outcome as a host that refuses an algorithm it does implement.
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    const cp = tampered.vaultCheckpoints[0]!;
    const key = tampered.signingKeys.find((k) => k.key_id === cp.signing_key_id)!;
    // X25519 has no COSE signature registration, so it resolves as
    // unrecognized and reaches the unsupported outcome without first
    // tripping the header-alg comparison.
    key.public_key = (
      generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' }) as Buffer
    ).toString('base64');

    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    // The entry walk reports the same code first; this asserts the checkpoint site.
    const failure = report.failures.find(
      (f) => f.code === 'CHAIN_UNSUPPORTED_ALGORITHM' && f.message.includes('checkpoint'),
    );
    expect(failure).toBeDefined();
    expect(failure!.message).toContain('could NOT BE CHECKED');
    // The fragment needs a subject in front of it or the sentence is
    // subjectless, in the one output whose whole job is to be unambiguous.
    expect(failure!.message).toContain(`Its signing key ${cp.signing_key_id} commits to`);
    expect(failure!.message).not.toContain('does not verify');
  });

  it('CHECKPOINT_SIGNATURE_INVALID when a checkpoint claiming a key carries an all-zero signature', () => {
    // The engine never writes a signing_key_id it did not sign with, so a
    // zeroed signature slot on a key-claiming checkpoint is tampering. This
    // pins the closed fail-open: the 'unsigned' outcome must not pass here.
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    const cp = tampered.vaultCheckpoints[0]!;
    const buf = Buffer.from(cp.cose_sign1, 'base64');
    buf.fill(0, buf.length - 64);
    cp.cose_sign1 = buf.toString('base64');
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHECKPOINT_SIGNATURE_INVALID')).toBe(true);
  });

  it('CHAIN_SIGNATURE_MISSING_KEY when a checkpoint carries signing_key_id ""', () => {
    // Only null means unsigned. A tampered checkpoint with an empty-string key
    // id must not slip past the signature check on a truthiness shortcut.
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.vaultCheckpoints[0]!.signing_key_id = '';
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHAIN_SIGNATURE_MISSING_KEY')).toBe(true);
  });

  it('CHAIN_SIGNATURE_MISSING_KEY when registry omits the signing key', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.signingKeys = [];
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHAIN_SIGNATURE_MISSING_KEY')).toBe(true);
  });

  it('CHAIN_PAYLOAD_BINDING_MISMATCH when the denormalised row payload is altered after signing', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    // Alter only the visible row payload; cose_sign1 still carries the original.
    tampered.vaultEntries[1]!.payload = { kind: 'transition', m: 'TAMPERED', n: 99 };
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHAIN_PAYLOAD_BINDING_MISMATCH')).toBe(true);
  });

  it('CHAIN_OIDC_ACTOR_MISMATCH when actor_oidc columns diverge from the signed predicate', () => {
    const key = generateKey();
    const e1 = buildVaultEntry({
      recordId: 'record-oidc',
      position: 1,
      previousHash: null,
      entryType: 'RECORD_CREATED',
      payload: { kind: 'create' },
      key,
      oidc: { iss: 'https://idp.example', sub: 'user-1' },
    });
    // Tamper the denormalised actor column away from the signed identity.
    e1.actor_oidc_sub = 'user-ATTACKER';
    const report = verifyVaultChains([e1], [], [signingKeyDump(key)]);
    expect(report.failures.some((f) => f.code === 'CHAIN_OIDC_ACTOR_MISMATCH')).toBe(true);
  });

  it('CHECKPOINT_HASH_MISMATCH when checkpoint disagrees with the live entry', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.vaultCheckpoints[0]!.payload_hash = 'ee'.repeat(32);
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHECKPOINT_HASH_MISMATCH')).toBe(true);
  });

  it('CHECKPOINT_ROW_MISSING when audit_vault was truncated past a checkpoint', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    const cp = tampered.vaultCheckpoints[0]!;
    tampered.vaultEntries = tampered.vaultEntries.filter((e) => e.record_id !== cp.record_id);
    const report = verifyVaultChains(tampered.vaultEntries, tampered.vaultCheckpoints, tampered.signingKeys);
    expect(report.failures.some((f) => f.code === 'CHECKPOINT_ROW_MISSING')).toBe(true);
  });

  // agents#103. A schema chain's checkpoint carries a derived UUIDv8 in
  // record_id, which matches no audit_vault row by inspection. Joining on that
  // column stranded the checkpoint and failed a healthy vault.
  const asSchemaChain = (dump: ReturnType<typeof cloneDump>, chainKey: string) => {
    const cp = dump.vaultCheckpoints[0]!;
    for (const e of dump.vaultEntries) {
      if (e.record_id === cp.record_id) e.chain_key = chainKey;
    }
    cp.chain_key = chainKey;
    // The derived v8 the engine writes: deliberately matches nothing.
    cp.record_id = '019a0000-0000-8000-8000-0000000000ff';
    return dump;
  };

  it('joins checkpoints on chain_key, so a healthy schema chain passes', () => {
    const { dump } = buildHappyDump();
    const d = asSchemaChain(cloneDump(dump), 'schema:org-1');
    const report = verifyVaultChains(d.vaultEntries, d.vaultCheckpoints, d.signingKeys);
    expect(report.failures).toEqual([]);
  });

  it('still catches a truncated schema chain, and names it by chain_key not record id', () => {
    const { dump } = buildHappyDump();
    const d = asSchemaChain(cloneDump(dump), 'schema:org-1');
    // Drop the row the checkpoint anchors: real tampering must still fail.
    const anchored = d.vaultEntries.filter((e) => e.chain_key === 'schema:org-1');
    d.vaultEntries = d.vaultEntries.filter((e) => e !== anchored[anchored.length - 1]);
    const report = verifyVaultChains(d.vaultEntries, d.vaultCheckpoints, d.signingKeys);
    const missing = report.failures.find((f) => f.code === 'CHECKPOINT_ROW_MISSING');
    expect(missing).toBeDefined();
    expect(missing!.scopeId).toBe('schema:org-1');
    expect(missing!.message).toContain('Chain schema:org-1');
    expect(missing!.message).not.toContain('RecordRow');
  });

  it('falls back to record_id when a pre-producer dump carries no chain_key', () => {
    const { dump } = buildHappyDump();
    const d = cloneDump(dump);
    for (const e of d.vaultEntries) delete e.chain_key;
    delete d.vaultCheckpoints[0]!.chain_key;
    const report = verifyVaultChains(d.vaultEntries, d.vaultCheckpoints, d.signingKeys);
    expect(report.failures).toEqual([]);
  });
});

describe('verifyOrgAdminReadsChains — adversarial cases', () => {
  it('TENANT_READ_LEAF_HASH_MISMATCH when cose_sign1 bytes are mutated', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.orgAdminReads[1]!.cose_sign1 = mutateBase64Byte(tampered.orgAdminReads[1]!.cose_sign1, -1);
    const report = verifyOrgAdminReadsChains(
      tampered.orgAdminReads,
      tampered.orgAdminReadsCheckpoints,
      tampered.signingKeys,
    );
    expect(report.failures.some((f) => f.code === 'TENANT_READ_LEAF_HASH_MISMATCH')).toBe(true);
  });

  it('TENANT_READ_LEAF_INDEX_GAP when a leaf is missing from the chain', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.orgAdminReads = tampered.orgAdminReads.filter(
      (l) => !(l.org_id === 'enterprise-1' && l.leaf_index === 1),
    );
    const report = verifyOrgAdminReadsChains(
      tampered.orgAdminReads,
      tampered.orgAdminReadsCheckpoints,
      tampered.signingKeys,
    );
    expect(report.failures.some((f) => f.code === 'TENANT_READ_LEAF_INDEX_GAP')).toBe(true);
  });

  it('TENANT_CHECKPOINT_ROOT_MISMATCH when stored root_hash is wrong', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.orgAdminReadsCheckpoints[0]!.root_hash = 'aa'.repeat(32);
    const report = verifyOrgAdminReadsChains(
      tampered.orgAdminReads,
      tampered.orgAdminReadsCheckpoints,
      tampered.signingKeys,
    );
    expect(report.failures.some((f) => f.code === 'TENANT_CHECKPOINT_ROOT_MISMATCH')).toBe(true);
  });

  it('TENANT_CHECKPOINT_SIGNATURE_INVALID when STH COSE_Sign1 signature is mutated', () => {
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    tampered.orgAdminReadsCheckpoints[0]!.cose_sign1 = mutateBase64Byte(
      tampered.orgAdminReadsCheckpoints[0]!.cose_sign1,
      -1,
    );
    const report = verifyOrgAdminReadsChains(
      tampered.orgAdminReads,
      tampered.orgAdminReadsCheckpoints,
      tampered.signingKeys,
    );
    expect(report.failures.some((f) => f.code === 'TENANT_CHECKPOINT_SIGNATURE_INVALID')).toBe(true);
  });

  it('TENANT_CHECKPOINT_SIGNATURE_INVALID when a key-claiming STH carries an all-zero signature', () => {
    // Closed fail-open pin, tenant side: an 'unsigned' outcome on a signed
    // tree head that claims a signing key must fail, not silently pass.
    const { dump } = buildHappyDump();
    const tampered = cloneDump(dump);
    const sth = tampered.orgAdminReadsCheckpoints[0]!;
    const buf = Buffer.from(sth.cose_sign1, 'base64');
    buf.fill(0, buf.length - 64);
    sth.cose_sign1 = buf.toString('base64');
    const report = verifyOrgAdminReadsChains(
      tampered.orgAdminReads,
      tampered.orgAdminReadsCheckpoints,
      tampered.signingKeys,
    );
    expect(report.failures.some((f) => f.code === 'TENANT_CHECKPOINT_SIGNATURE_INVALID')).toBe(true);
  });

  it('TENANT_CHECKPOINT_FORK when two checkpoints at same tree_size have different roots', () => {
    const { dump, key } = buildHappyDump();
    const tampered = cloneDump(dump);
    const altLeaves = [
      buildOrgAdminRead({ orgId: 'enterprise-1', leafIndex: 0, key, recordId: 'record-FORK-0' }),
      buildOrgAdminRead({ orgId: 'enterprise-1', leafIndex: 1, key, recordId: 'record-FORK-1' }),
      buildOrgAdminRead({ orgId: 'enterprise-1', leafIndex: 2, key, recordId: 'record-FORK-2' }),
    ];
    const altCp = buildOrgAdminReadsCheckpoint('enterprise-1', altLeaves, key, 3);
    altCp.id = 'oar-cp-fork';
    tampered.orgAdminReadsCheckpoints.push(altCp);
    const report = verifyOrgAdminReadsChains(
      tampered.orgAdminReads,
      tampered.orgAdminReadsCheckpoints,
      tampered.signingKeys,
    );
    expect(report.failures.some((f) => f.code === 'TENANT_CHECKPOINT_FORK')).toBe(true);
  });

  it('TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH when checkpoint signs more leaves than were dumped', () => {
    const { dump, key } = buildHappyDump();
    const tampered = cloneDump(dump);
    const realLeaves = tampered.orgAdminReads.filter((l) => l.org_id === 'enterprise-1');
    const phantomLeaves = [...realLeaves];
    for (let i = 0; i < 5; i++) {
      phantomLeaves.push(buildOrgAdminRead({ orgId: 'enterprise-1', leafIndex: realLeaves.length + i, key }));
    }
    tampered.orgAdminReadsCheckpoints = [buildOrgAdminReadsCheckpoint('enterprise-1', phantomLeaves, key)];
    const report = verifyOrgAdminReadsChains(
      tampered.orgAdminReads,
      tampered.orgAdminReadsCheckpoints,
      tampered.signingKeys,
    );
    expect(report.failures.some((f) => f.code === 'TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH')).toBe(true);
  });
});
