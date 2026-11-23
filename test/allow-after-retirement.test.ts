/**
 * `--allow-after-retirement`, on both surfaces. A sealed federation message
 * signed by a peer key more than 300 seconds after that key's retirement
 * fails by default; with the flag it verifies and is counted. The keys are the
 * test keys of a peer that rotated K1 to K2 to K3 (`keys.json`), with the
 * history a Server served for them (`succession.json`): K1 retired at
 * 04:22:03.323630Z.
 */
import { createHash, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import { canonicalizeJson, federationSignInput } from '@agledger/verify-core';
import { EXIT_OK, EXIT_VERIFICATION_FAILED, parseArgs, runCli } from '../src/cli.js';
import { DEFAULT_FILENAMES, loadDump } from '../src/loader.js';
import { verifyDump } from '../src/dump-verifier.js';
import type { Dump } from '../src/types.js';
import { buildHappyDump, buildVaultEntry } from './fixtures.js';

const FIXTURES = join(import.meta.dirname, 'fixtures', 'federation-key-history');
const keys = JSON.parse(readFileSync(join(FIXTURES, 'keys.json'), 'utf8')) as {
  instanceId: string;
  K1: { privateKey: string; publicKey: string };
  K3: { privateKey: string; publicKey: string };
};
const HUB = keys.instanceId;
const HISTORY = join(FIXTURES, 'succession.json');
const WITHIN_ALLOWANCE = '2026-11-05T04:22:05.000Z';
const AFTER_RETIREMENT = '2026-11-05T04:27:03.324Z';

const bodyFor = (recordId: string) => ({
  recordId,
  state: 'FULFILLED',
  type: 'principal-gate-generic-v1',
  idempotencyKey: '0199a8f0-0000-7000-8000-00000000c0de',
  schemaRef: { type: 'principal-gate-generic-v1', manifestDigest: 'sha256:' + 'ab'.repeat(32) },
  principalAgentId: '0199a8f0-0000-7000-8000-000000000001',
  performerAgentId: '0199a8f0-0000-7000-8000-000000000002',
});

/** A message the peer signed under K1 at `timestamp`, sealed as the receiving Server seals it. */
function projectionSignedAt(timestamp: string, recordId: string): Record<string, unknown> {
  const body = bodyFor(recordId);
  const wire = {
    scheme: 'agledger.federation.v2',
    senderHubId: HUB,
    senderPublicKey: keys.K1.publicKey,
    recipientHubId: 'hub-receiver',
    method: 'POST',
    path: '/federation/v1/state-transition',
    bodyHash: createHash('sha256').update(canonicalizeJson(body), 'utf8').digest('hex'),
    timestamp,
    nonce: 'a1b2c3d4e5f60718a1b2c3d4e5f60718',
    signature: '',
    body,
  };
  const priv = { key: Buffer.from(keys.K1.privateKey, 'base64'), format: 'der' as const, type: 'pkcs8' as const };
  wire.signature = sign(null, Buffer.from(federationSignInput(wire as never), 'utf8'), priv).toString('hex');
  return {
    peerHubId: HUB,
    recordType: body.type,
    state: body.state,
    principalAgentId: body.principalAgentId,
    performerAgentId: body.performerAgentId,
    schemaRef: body.schemaRef,
    outcome: 'inserted',
    wire,
  };
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'agledger-verify-after-retirement-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const peerFlags = ['--federation-key', `${HUB}=${keys.K3.publicKey}`, '--federation-key-history', HISTORY, '-f', 'json'];

/** The happy dump with its first record's second entry replaced by a sealed peer message. */
function dumpWithMessage(timestamp: string): string {
  const { dump, key } = buildHappyDump();
  const first = dump.vaultEntries[0]!;
  const message = buildVaultEntry({
    recordId: 'record-aaaa',
    position: 2,
    previousHash: first.payload_hash,
    entryType: 'FEDERATION_STATE_SYNC',
    payload: projectionSignedAt(timestamp, first.record_id),
    key,
  });
  const next: Dump = { ...dump, vaultEntries: [first, message], vaultCheckpoints: [] };
  const files: Record<keyof typeof DEFAULT_FILENAMES, readonly unknown[]> = {
    vaultEntries: next.vaultEntries,
    vaultCheckpoints: next.vaultCheckpoints,
    signingKeys: next.signingKeys,
    keyStatements: next.keyStatements,
    orgAdminReads: next.orgAdminReads,
    orgAdminReadsCheckpoints: next.orgAdminReadsCheckpoints,
  };
  for (const [k, name] of Object.entries(DEFAULT_FILENAMES) as Array<[keyof typeof DEFAULT_FILENAMES, string]>) {
    writeFileSync(join(dir, name), files[k].map((r) => JSON.stringify(r)).join('\n') + '\n');
  }
  return dir;
}

/** The conformance export with entry 1 rewritten as a sealed peer message and the chain re-signed under a key this test holds. */
function exportWithMessage(timestamp: string): string {
  const exp = JSON.parse(readFileSync(join(import.meta.dirname, '..', 'testdata', 'conformance', 'export', 'valid.json'), 'utf8')) as {
    entries: Array<{ recordId: string; entryType: string; payload: unknown; integrity: Record<string, unknown> }>;
    exportMetadata: Record<string, unknown>;
  };
  const vault = buildHappyDump().key;
  const priv = { key: Buffer.from(vault.privateKeyDerB64, 'base64'), format: 'der' as const, type: 'pkcs8' as const };
  const payload = projectionSignedAt(timestamp, exp.entries[1]!.recordId);
  let prev: Buffer | null = null;
  exp.entries.forEach((e, i) => {
    const [prot0, , payload0] = cborDecode(Buffer.from(e.integrity['coseSign1'] as string, 'base64').subarray(1), { useMaps: true }) as [Uint8Array, unknown, Uint8Array];
    let payloadBstr = payload0;
    if (i === 1) {
      const stmt = cborDecode(payload0, { useMaps: false }) as Record<string, unknown>;
      const signed = stmt['predicate'] as Record<string, unknown>;
      const rebuilt: Record<string, unknown> = { record_id: signed['record_id'], entry_type: 'FEDERATION_STATE_SYNC', payload };
      for (const k of ['on_behalf_of', 'traceparent']) if (k in signed) rebuilt[k] = signed[k];
      stmt['predicate'] = rebuilt;
      payloadBstr = cborEncode(stmt, rfc8949EncodeOptions);
      e.entryType = 'FEDERATION_STATE_SYNC';
      e.payload = payload;
    }
    const header = cborDecode(prot0, { useMaps: true }) as Map<number, unknown>;
    header.set(4, Uint8Array.from(Buffer.from(vault.keyId, 'hex')));
    (header.get(-65537) as Map<number, unknown>).set(2, prev === null ? null : Uint8Array.from(prev));
    const prot = cborEncode(header, rfc8949EncodeOptions);
    const sig = sign(null, cborEncode(['Signature1', prot, new Uint8Array(0), payloadBstr], rfc8949EncodeOptions), priv);
    const envelope = Buffer.concat([Buffer.from([0xd2]), Buffer.from(cborEncode([prot, new Map(), payloadBstr, Uint8Array.from(sig)], rfc8949EncodeOptions))]);
    const hash = createHash('sha256').update(envelope).digest();
    e.integrity['coseSign1'] = envelope.toString('base64');
    e.integrity['payloadHash'] = hash.toString('hex');
    e.integrity['previousHash'] = prev === null ? null : prev.toString('hex');
    e.integrity['signingKeyId'] = vault.keyId;
    prev = hash;
  });
  const m = exp.exportMetadata;
  m['signingPublicKeys'] = { [vault.keyId]: vault.publicKeyDerB64 };
  m['signingKeyWindows'] = { [vault.keyId]: { activatedAt: '2026-09-01T00:00:00.000Z', retiredAt: null } };
  delete m['signingKeyStatements'];
  delete m['anchoredFrom'];
  const path = join(dir, 'export.json');
  writeFileSync(path, JSON.stringify(exp));
  return path;
}

interface Json {
  verdict?: string;
  valid?: boolean;
  federationWire?: { present: number; verified: number; failed: number; afterRetirement: number };
  vault?: { federationWire: { present: number; verified: number; failed: number; afterRetirement: number }; failures: Array<{ code: string; message: string }> };
  brokenAt?: { code: string; detail: string };
}

const run = (target: string, extra: string[] = []): { exitCode: number; out: Json; stdout: string } => {
  const r = runCli([target, ...peerFlags, ...extra]);
  return { exitCode: r.exitCode, out: JSON.parse(r.stdout) as Json, stdout: r.stdout };
};

describe('parseArgs --allow-after-retirement', () => {
  it('is a boolean that defaults to off', () => {
    expect(parseArgs(['x']).allowAfterRetirement).toBe(false);
    expect(parseArgs(['x', '--allow-after-retirement']).allowAfterRetirement).toBe(true);
  });
});

describe('an /audit-export with a peer message signed after its key retired', () => {
  it('fails by default, and the failure names the flag', () => {
    const r = run(exportWithMessage(AFTER_RETIREMENT));
    expect(r.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    expect(r.out.brokenAt?.code).toBe('CHAIN_FEDERATION_WIRE_INVALID');
    expect(r.out.brokenAt?.detail).toContain('--allow-after-retirement');
  });

  it('verifies and is counted with the flag', () => {
    const r = run(exportWithMessage(AFTER_RETIREMENT), ['--allow-after-retirement']);
    expect(r.exitCode).toBe(EXIT_OK);
    expect(r.out.federationWire).toEqual({ present: 1, verified: 1, failed: 0, afterRetirement: 1 });
  });

  it('passes without the flag when the message is within the allowance, and is not counted', () => {
    const r = run(exportWithMessage(WITHIN_ALLOWANCE));
    expect(r.exitCode).toBe(EXIT_OK);
    expect(r.out.federationWire).toEqual({ present: 1, verified: 1, failed: 0, afterRetirement: 0 });
  });
});

describe('a dump with a peer message signed after its key retired', () => {
  it('fails by default, and the failure names the flag', () => {
    const r = run(dumpWithMessage(AFTER_RETIREMENT));
    expect(r.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    const failure = r.out.vault?.failures.find((f) => f.code === 'CHAIN_FEDERATION_WIRE_INVALID');
    expect(failure?.message).toContain('--allow-after-retirement');
  });

  it('verifies and is counted with the flag', () => {
    const r = run(dumpWithMessage(AFTER_RETIREMENT), ['--allow-after-retirement']);
    expect(r.exitCode).toBe(EXIT_OK);
    expect(r.out.vault?.failures).toEqual([]);
    expect(r.out.vault?.federationWire).toEqual({ present: 1, verified: 1, failed: 0, afterRetirement: 1 });
  });

  it('reads allowAfterRetirement as a library option too', () => {
    const history = JSON.parse(readFileSync(HISTORY, 'utf8')) as never;
    const federationKeys = [{ hubId: HUB, publicKey: keys.K3.publicKey, history }];
    const loaded = dumpWithMessage(AFTER_RETIREMENT);
    const off = verifyDump(loadDump(loaded), { federationKeys });
    const on = verifyDump(loadDump(loaded), { federationKeys, allowAfterRetirement: true });
    expect(off.vault.failureCount).toBeGreaterThan(0);
    expect(on.vault.failureCount).toBe(0);
    expect(on.vault.federationWire.afterRetirement).toBe(1);
  });
});
