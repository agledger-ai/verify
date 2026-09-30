/**
 * The cert public keys a dump signs itself. Each EPHEMERAL_CERT_ISSUED entry
 * on the platform-ops chain signs its cert's `publicKeyJwk`, so a dump not
 * scoped to one org can re-verify sealed agent signatures without
 * `--agent-keys`. A key is used only when it sits on a chain this verifier has
 * verified clean, under an entry whose vault signature checked.
 *
 * Corpus cases mutate `dump/valid-identity` (the platform-ops chain, three
 * cert issuances under one agent key, and a record chain carrying a sealed
 * agent signature made with it) and use `dump/identity-key-rotated-tampered`
 * as generated. Where a case needs an agent signature that does not verify,
 * the dump is synthetic, because a real entry cannot carry one without also
 * breaking its vault signature.
 */
import { generateKeyPairSync, hash, sign as nodeSign } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { AGENT_SIGNATURE_CONTEXT, ed25519JwkThumbprint, type AgentPublicKeyJwk } from '@agledger/verify-core';
import { loadDump } from '../src/loader.js';
import { verifyDump } from '../src/dump-verifier.js';
import { EXIT_OK, runCli } from '../src/cli.js';
import type { Dump } from '../src/types.js';
import { buildVaultEntry, generateKey, signingKeyDump } from './fixtures.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DUMPS = join(HERE, '..', 'testdata', 'conformance', 'dump');
const PLATFORM = '00000000-0000-0000-0000-000000000000';

function identity(): Dump {
  return loadDump(join(DUMPS, 'valid-identity'));
}

describe('a full dump re-verifies agent signatures from its own cert keys', () => {
  it('valid-identity verifies its sealed agent signature with no --agent-keys', () => {
    const report = verifyDump(identity());
    expect(report.verdict).toBe('unanchored');
    // Three issuances, one agent key: counted once.
    expect(report.vault.certKeysFromChain).toBe(1);
    expect(report.vault.optionalChecks.agent_signature).toBe('applied');
    expect(report.vault.agentSignatures).toEqual({ present: 1, verified: 1 });
  });

  it('says where the key came from in the text report', () => {
    const r = runCli([join(DUMPS, 'valid-identity')]);
    expect(r.exitCode).toBe(EXIT_OK);
    expect(r.stdout).toContain('agent sigs  : present=1 verified=1 (all re-verified against the 1 cert key the dump signs)');
  });

  it('an org-scoped dump, which leaves the platform-ops chain out, harvests nothing', () => {
    const dump = identity();
    dump.vaultEntries = dump.vaultEntries.filter((e) => e.chain_key !== PLATFORM);
    dump.vaultCheckpoints = dump.vaultCheckpoints.filter((c) => c.chain_key !== PLATFORM);
    const report = verifyDump(dump);
    expect(report.verdict).toBe('unanchored');
    expect(report.vault.certKeysFromChain).toBe(0);
    expect(report.vault.optionalChecks.agent_signature).toBe('skipped_no_input');
    expect(report.vault.agentSignatures).toEqual({ present: 1, verified: 0 });
  });
});

describe('a key is used only from a chain the verifier has verified', () => {
  it('not when another entry on the platform-ops chain fails (identity-key-rotated-tampered)', () => {
    const report = verifyDump(loadDump(join(DUMPS, 'identity-key-rotated-tampered')));
    expect(report.vault.failures.map((f) => [f.code, f.scopeId])).toEqual([
      ['CHAIN_PAYLOAD_BINDING_MISMATCH', PLATFORM],
    ]);
    // The cert entries themselves are intact, and still not trusted.
    expect(report.vault.certKeysFromChain).toBe(0);
    expect(report.vault.agentSignatures).toEqual({ present: 1, verified: 0 });
  });

  it('not when the platform-ops chain diverges from its own checkpoint', () => {
    const dump = identity();
    const cp = dump.vaultCheckpoints.find((c) => c.chain_key === PLATFORM)!;
    cp.payload_hash = 'a'.repeat(64);
    const report = verifyDump(dump);
    expect(report.vault.failures.map((f) => f.code)).toEqual(['CHECKPOINT_HASH_MISMATCH']);
    expect(report.vault.certKeysFromChain).toBe(0);
    expect(report.vault.agentSignatures.verified).toBe(0);
  });

  it('not from an unsigned entry, even on a chain that verifies', () => {
    const dump = identity();
    const platform = dump.vaultEntries.filter((e) => e.chain_key === PLATFORM);
    const records = dump.vaultEntries.filter((e) => e.chain_key !== PLATFORM);
    // Written before the install signed: keep the platform-ops entries that
    // predate every record entry, unsign them, and activate the key between.
    const firstRecordAt = Math.min(...records.map((e) => Date.parse(e.created_at)));
    const early = platform.filter((e) => Date.parse(e.created_at) < firstRecordAt);
    expect(early.some((e) => e.entry_type === 'EPHEMERAL_CERT_ISSUED')).toBe(true);
    for (const e of early) e.signing_key_id = null;
    dump.vaultEntries = [...early, ...records];
    dump.vaultCheckpoints = dump.vaultCheckpoints.filter(
      (c) => c.chain_key !== PLATFORM || c.chain_position <= early.length,
    );
    dump.signingKeys[0]!.activated_at = new Date(firstRecordAt - 1).toISOString();
    const report = verifyDump(dump);
    expect(report.verdict, JSON.stringify(report.vault.failures)).toBe('unanchored');
    expect(report.vault.certKeysFromChain).toBe(0);
    expect(report.vault.agentSignatures).toEqual({ present: 1, verified: 0 });
  });

  it('not when a row copy of the key was rewritten, which fails the chain', () => {
    const dump = identity();
    const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as AgentPublicKeyJwk;
    for (const e of dump.vaultEntries) {
      if (e.entry_type === 'EPHEMERAL_CERT_ISSUED') e.payload = { ...e.payload, publicKeyJwk: other };
    }
    const report = verifyDump(dump);
    expect(report.vault.failures.every((f) => f.code === 'CHAIN_PAYLOAD_BINDING_MISMATCH')).toBe(true);
    expect(report.vault.certKeysFromChain).toBe(0);
  });
});

describe('a harvested key decides a verdict the way a supplied one does', () => {
  /**
   * A platform-ops chain issuing one cert, then a record chain whose sealed
   * agent signature was made with that cert's key over `signedBody`.
   */
  function synthetic(opts: {
    badSignature: boolean;
    certChainFirst?: boolean;
    breakCertChain?: boolean;
    issuedType?: string;
  }): Dump {
    const vaultKey = generateKey();
    const agent = generateKeyPairSync('ed25519');
    const jwk = agent.publicKey.export({ format: 'jwk' }) as AgentPublicKeyJwk;
    const contentHash = hash('sha256', '{"type":"example"}', 'hex');
    const signed = opts.badSignature ? hash('sha256', 'a different body', 'hex') : contentHash;
    const signature = nodeSign(null, Buffer.from(`${AGENT_SIGNATURE_CONTEXT}${signed}`), agent.privateKey).toString(
      'base64',
    );
    const issued = buildVaultEntry({
      recordId: 'platform-ops',
      position: 1,
      previousHash: null,
      entryType: opts.issuedType ?? 'EPHEMERAL_CERT_ISSUED',
      payload: { certId: 'cert-1', publicKeyJwk: jwk, publicKeyThumbprint: ed25519JwkThumbprint(jwk) },
      key: vaultKey,
    });
    if (opts.breakCertChain) issued.previous_hash = 'b'.repeat(64);
    const record = buildVaultEntry({
      recordId: 'record-agent-signed',
      position: 1,
      previousHash: null,
      entryType: 'RECORD_CREATED',
      payload: { kind: 'create' },
      key: vaultKey,
      onBehalfOf: {
        validated: true,
        cert: { id: 'cert-1', thumbprint: ed25519JwkThumbprint(jwk) },
        agent_signature: { alg: 'EdDSA', signature, content_hash: `sha256:${contentHash}` },
      },
    });
    return {
      vaultEntries: opts.certChainFirst === false ? [record, issued] : [issued, record],
      vaultCheckpoints: [],
      signingKeys: [signingKeyDump(vaultKey)],
      keyStatements: [],
      orgAdminReads: [],
      orgAdminReadsCheckpoints: [],
    };
  }

  it('a good agent signature verifies', () => {
    const report = verifyDump(synthetic({ badSignature: false }));
    expect(report.verdict).toBe('unanchored');
    expect(report.vault.agentSignatures).toEqual({ present: 1, verified: 1 });
  });

  it('a bad one fails CHAIN_AGENT_SIGNATURE_INVALID with no --agent-keys', () => {
    const report = verifyDump(synthetic({ badSignature: true }));
    expect(report.vault.failures.map((f) => f.code)).toEqual(['CHAIN_AGENT_SIGNATURE_INVALID']);
  });

  it('a key from a cert chain that fails verification is not used', () => {
    const report = verifyDump(synthetic({ badSignature: true, breakCertChain: true }));
    expect(report.vault.failures.map((f) => f.code)).toEqual(['CHAIN_GENESIS_INVALID']);
    expect(report.vault.certKeysFromChain).toBe(0);
    expect(report.vault.optionalChecks.agent_signature).toBe('skipped_no_input');
  });

  it('a publicKeyJwk under any other entry type is not a cert key', () => {
    const report = verifyDump(synthetic({ badSignature: true, issuedType: 'AUTH_KEY_ROTATED' }));
    expect(report.verdict).toBe('unanchored');
    expect(report.vault.certKeysFromChain).toBe(0);
  });

  it('a record chain met before the cert chain goes unchecked, never misjudged', () => {
    const report = verifyDump(synthetic({ badSignature: true, certChainFirst: false }));
    expect(report.verdict).toBe('unanchored');
    expect(report.vault.certKeysFromChain).toBe(1);
    expect(report.vault.agentSignatures).toEqual({ present: 1, verified: 0 });
  });
});
