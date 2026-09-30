/**
 * `--agent-keys` and the offline agent-signature check, on both surfaces.
 *
 * The live fixtures under `fixtures/live-1.8.0/` are unmodified output of an
 * API 1.8.0 instance: `export-cert-lifecycle.json` is one record driven end to
 * end by an agent on an ephemeral cert that signed every request body, and
 * `agent-cert-key.json` is the key that agent sent at cert exchange. The dump
 * is a slice of a full vault dump from the same instance, cut to three whole
 * record chains: that cert-signed lifecycle (6 agent signatures), a lifecycle
 * signed under a different cert whose key was never kept (6), and an unsigned
 * API-key lifecycle. Every run is pinned on that instance's vault key, so a
 * clean run is a PASS rather than NOT ANCHORED.
 */
import { generateKeyPairSync, hash, sign as nodeSign } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AGENT_SIGNATURE_CONTEXT, ed25519JwkThumbprint, type AgentPublicKeyJwk } from '@agledger/verify-core';
import { EXIT_CANNOT_VERIFY, EXIT_OK, EXIT_VERIFICATION_FAILED, parseArgs, runCli as runCliUnpinned } from '../src/cli.js';
import { verifyDump } from '../src/dump-verifier.js';
import { verifyDumpStreaming } from '../src/verify-dir.js';
import type { VaultEntryDump, VerifyReport } from '../src/types.js';
import { LIVE_PIN, buildVaultEntry, generateKey, liveDumpCopy, pinOf, signingKeyDump } from './fixtures.js';

const here = dirname(fileURLToPath(import.meta.url));
const LIVE = join(here, 'fixtures', 'live-1.8.0');
const EXPORT = join(LIVE, 'export-cert-lifecycle.json');
const DUMP = liveDumpCopy();
afterAll(() => rmSync(DUMP, { recursive: true, force: true }));
const runCli = (argv: readonly string[]) => runCliUnpinned([...argv, '--trust-anchor', LIVE_PIN]);
const KEY_FILE = join(LIVE, 'agent-cert-key.json');
const keyEntry = JSON.parse(readFileSync(KEY_FILE, 'utf-8')) as {
  publicKeyThumbprint: string;
  publicKeyJwk: AgentPublicKeyJwk;
};
const JWK = keyEntry.publicKeyJwk;

function otherJwk(): AgentPublicKeyJwk {
  const { publicKey } = generateKeyPairSync('ed25519');
  return publicKey.export({ format: 'jwk' }) as AgentPublicKeyJwk;
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'agledger-verify-agent-keys-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function writeJson(name: string, value: unknown): string {
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify(value));
  return path;
}

function json<T>(stdout: string): T {
  return JSON.parse(stdout) as T;
}

interface ExportJson {
  valid: boolean;
  optionalChecks: { agent_signature: string };
  agentSignatures: { present: number; verified: number };
  brokenAt?: { code: string };
}

describe('parseArgs --agent-keys', () => {
  it('takes the value as a separate argument or with =', () => {
    expect(parseArgs(['x', '--agent-keys', 'k.json']).agentKeys).toBe('k.json');
    expect(parseArgs(['x', '--agent-keys=k.json']).agentKeys).toBe('k.json');
    expect(parseArgs(['x']).agentKeys).toBeNull();
  });

  it('rejects a missing value', () => {
    expect(() => parseArgs(['x', '--agent-keys'])).toThrow(/--agent-keys requires a value/);
    expect(() => parseArgs(['x', '--agent-keys='])).toThrow(/--agent-keys requires a value/);
  });
});

describe('the live key fixture', () => {
  it('is the key the cert-signed entries name by thumbprint', () => {
    expect(ed25519JwkThumbprint(JWK)).toBe(keyEntry.publicKeyThumbprint);
  });
});

describe('--agent-keys on an /audit-export file', () => {
  it('re-verifies every agent signature on the live cert lifecycle', () => {
    const r = runCli([EXPORT, '--agent-keys', KEY_FILE, '-f', 'json']);
    expect(r.exitCode).toBe(EXIT_OK);
    const out = json<ExportJson>(r.stdout);
    expect(out.valid).toBe(true);
    expect(out.optionalChecks.agent_signature).toBe('applied');
    expect(out.agentSignatures).toEqual({ present: 6, verified: 6 });
  });

  it('says so in the text report', () => {
    const r = runCli([EXPORT, '--agent-keys', KEY_FILE]);
    expect(r.exitCode).toBe(EXIT_OK);
    expect(r.stdout).toContain('agent signatures  : present=6 verified=6 (all re-verified against the supplied keys)');
  });

  it('without keys reports the check as not run and changes no verdict', () => {
    const r = runCli([EXPORT, '-f', 'json']);
    expect(r.exitCode).toBe(EXIT_OK);
    const out = json<ExportJson>(r.stdout);
    expect(out.optionalChecks.agent_signature).toBe('skipped_no_input');
    expect(out.agentSignatures).toEqual({ present: 6, verified: 0 });
    expect(runCli([EXPORT]).stdout).toContain('present=6 verified=0 (NOT verified: pass --agent-keys');
  });

  it.each([
    ['a bare JWK', () => JWK],
    ['a list of JWKs', () => [otherJwk(), JWK]],
    ['a {keys:[...]} JWK Set', () => ({ keys: [JWK, otherJwk()] })],
    ['a {publicKeyJwk} entry', () => keyEntry],
    ['a list of {publicKeyJwk} entries', () => [{ publicKeyJwk: otherJwk() }, keyEntry]],
    ['a JWK Set of {publicKeyJwk} entries', () => ({ keys: [keyEntry] })],
  ])('accepts %s', (_label, shape) => {
    const r = runCli([EXPORT, '--agent-keys', writeJson('keys.json', shape()), '-f', 'json']);
    expect(r.exitCode).toBe(EXIT_OK);
    expect(json<ExportJson>(r.stdout).agentSignatures).toEqual({ present: 6, verified: 6 });
  });

  it('a key for some other cert matches nothing and checks nothing', () => {
    const r = runCli([EXPORT, '--agent-keys', writeJson('keys.json', [otherJwk()]), '-f', 'json']);
    expect(r.exitCode).toBe(EXIT_OK);
    const out = json<ExportJson>(r.stdout);
    expect(out.optionalChecks.agent_signature).toBe('skipped_no_input');
    expect(out.agentSignatures).toEqual({ present: 6, verified: 0 });
  });

  it('says the supplied keys matched nothing, rather than asking for --agent-keys', () => {
    const r = runCli([EXPORT, '--agent-keys', writeJson('keys.json', [otherJwk()])]);
    expect(r.exitCode).toBe(EXIT_OK);
    expect(r.stdout).toContain(
      'agent signatures  : present=6 verified=0 (NOT verified: none of the supplied keys matches the cert thumbprint',
    );
    expect(r.stdout).not.toContain('pass --agent-keys');
  });
});

describe('the agent-signature line never reads as covering unverified signatures', () => {
  // Every PASS text report on a chain carrying agent signatures either says
  // all were re-verified or says NOT verified.
  it.each([
    ['export, no keys', () => [EXPORT]],
    ['export, unmatched key', () => [EXPORT, '--agent-keys', writeJson('k.json', otherJwk())]],
    ['dump, no keys', () => [DUMP]],
    ['dump, unmatched key', () => [DUMP, '--agent-keys', writeJson('k.json', otherJwk())]],
    ['dump, partial key set', () => [DUMP, '--agent-keys', KEY_FILE]],
  ])('%s', (_label, argv) => {
    const r = runCli(argv());
    expect(r.stdout.startsWith('[PASS]')).toBe(true);
    const line = r.stdout.split('\n').find((l) => /agent sig/.test(l))!;
    expect(line).toMatch(/NOT verified/);
    expect(line).not.toMatch(/all re-verified/);
  });

  it('dump, unmatched key names the mismatch', () => {
    const r = runCli([DUMP, '--agent-keys', writeJson('k.json', otherJwk())]);
    expect(r.stdout).toContain('agent sigs  : present=12 verified=0 (NOT verified: none of the supplied keys matches');
  });
});

describe('a malformed --agent-keys file is a usage error, in both modes', () => {
  const cases: Array<[string, () => string, RegExp]> = [
    ['a missing file', () => join(dir, 'nope.json'), /Cannot read --agent-keys file .*nope\.json/],
    [
      'invalid JSON',
      () => {
        const p = join(dir, 'bad.json');
        writeFileSync(p, '{not json');
        return p;
      },
      /Cannot read --agent-keys file/,
    ],
    ['an empty list', () => writeJson('empty.json', []), /holds no keys/],
    ['an empty JWK Set', () => writeJson('empty-set.json', { keys: [] }), /holds no keys/],
    [
      'a non-Ed25519 JWK',
      () => writeJson('ec.json', [JWK, { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }]),
      /entry 1 is not an Ed25519 public-key JWK/,
    ],
    ['an SPKI string', () => writeJson('spki.json', ['MCowBQYDK2VwAyEA']), /entry 0 is not an Ed25519/],
    ['a short x', () => writeJson('short.json', { ...JWK, x: 'AAAA' }), /entry 0 is not an Ed25519/],
  ];

  for (const target of [EXPORT, DUMP]) {
    const mode = target === DUMP ? 'dump' : 'export';
    it.each(cases)(`${mode}: %s`, (_label, file, message) => {
      const path = file();
      const text = runCli([target, '--agent-keys', path]);
      expect(text.exitCode).toBe(EXIT_CANNOT_VERIFY);
      expect(text.stdout).toBe('');
      expect(text.stderr).toMatch(message);

      const machine = runCli([target, '--agent-keys', path, '-f', 'json']);
      expect(machine.exitCode).toBe(EXIT_CANNOT_VERIFY);
      const body = json<{ ok: boolean; error: { kind: string; message: string } }>(machine.stdout);
      expect(body.ok).toBe(false);
      expect(body.error.kind).toBe('input');
      expect(body.error.message).toMatch(message);
    });
  }
});

describe('--agent-keys on a dump directory', () => {
  it('is accepted, unlike the export-only key-policy flags', () => {
    expect(runCli([DUMP, '--agent-keys', KEY_FILE]).exitCode).toBe(EXIT_OK);
    expect(runCli([DUMP, '--keys', KEY_FILE]).exitCode).toBe(EXIT_CANNOT_VERIFY);
  });

  it('re-verifies the signatures under the supplied cert and leaves the others unchecked', () => {
    const r = runCli([DUMP, '--agent-keys', KEY_FILE, '-f', 'json']);
    expect(r.exitCode).toBe(EXIT_OK);
    const report = json<VerifyReport>(r.stdout);
    expect(report.ok).toBe(true);
    expect(report.vault.entryCount).toBe(27);
    expect(report.vault.optionalChecks).toEqual({
      payload_binding: 'applied',
      oidc_actor: 'applied',
      actor_attribution: 'applied',
      // An API 1.8.0 dump carries no key statements, so the pinned key has no
      // signed window to hold entries to.
      key_temporal: 'skipped_no_input',
      agent_signature: 'applied',
      key_anchoring: 'applied',
    });
    expect(report.vault.agentSignatures).toEqual({ present: 12, verified: 6 });
  });

  it('says which signatures were checked in the text report', () => {
    const r = runCli([DUMP, '--agent-keys', KEY_FILE]);
    expect(r.stdout).toContain('agent sigs  : present=12 verified=6 (6 NOT verified: no key for their cert');
    expect(runCli([DUMP]).stdout).toContain('agent sigs  : present=12 verified=0 (NOT verified: pass --agent-keys');
  });

  it('without keys reports the check as not run and changes no verdict', () => {
    const report = verifyDumpStreaming(DUMP, undefined, { trustAnchors: [LIVE_PIN] });
    expect(report.ok).toBe(true);
    expect(report.vault.optionalChecks.agent_signature).toBe('skipped_no_input');
    expect(report.vault.agentSignatures).toEqual({ present: 12, verified: 0 });
  });

  it('the library entry point takes the keys directly', () => {
    const report = verifyDumpStreaming(DUMP, undefined, { agentKeys: [JWK] });
    expect(report.vault.agentSignatures).toEqual({ present: 12, verified: 6 });
  });
});

function readSlice(): VaultEntryDump[] {
  return readFileSync(join(DUMP, 'audit_vault.ndjson'), 'utf-8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as VaultEntryDump);
}

function writeSlice(rows: readonly VaultEntryDump[]): string {
  const out = join(dir, 'dump');
  cpSync(DUMP, out, { recursive: true });
  writeFileSync(join(out, 'audit_vault.ndjson'), rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  return out;
}

describe('a row copy of on_behalf_of must equal what the entry signed (live dump)', () => {
  // The cert-signed create: its signed predicate carries on_behalf_of, and the
  // engine does not copy it onto the row payload.
  const target = (r: VaultEntryDump): boolean =>
    r.record_id === '01a0b33c-e284-7530-a9f3-d65dbdcca261' && r.chain_position === 1;

  it('the unmodified slice has no row copy and verifies', () => {
    const rows = readSlice();
    expect(rows.filter((r) => r.payload && 'on_behalf_of' in r.payload)).toHaveLength(0);
    expect(runCli([writeSlice(rows)]).exitCode).toBe(EXIT_OK);
  });

  it('a row on_behalf_of that differs from the signed one fails CHAIN_PAYLOAD_BINDING_MISMATCH', () => {
    const rows = readSlice();
    const row = rows.find(target)!;
    row.payload = {
      ...row.payload,
      on_behalf_of: { validated: true, oidc: { iss: 'https://idp.attacker.test', sub: 'someone-else' } },
    };
    const r = runCli([writeSlice(rows), '-f', 'json']);
    expect(r.exitCode).toBe(EXIT_VERIFICATION_FAILED);
    const report = json<VerifyReport>(r.stdout);
    expect(report.vault.failureCount).toBe(1);
    expect(report.vault.failures[0]).toMatchObject({
      code: 'CHAIN_PAYLOAD_BINDING_MISMATCH',
      scopeId: '01a0b33c-e284-7530-a9f3-d65dbdcca261',
      position: 1,
    });
  });

  it('a malformed traceparent row copy is dropped by the engine, so it does not bind', () => {
    const rows = readSlice();
    const row = rows.find(target)!;
    row.payload = { ...row.payload, traceparent: 'not-a-traceparent' };
    expect(runCli([writeSlice(rows)]).exitCode).toBe(EXIT_OK);
  });

  it('a well-formed traceparent the entry never signed fails CHAIN_PAYLOAD_BINDING_MISMATCH', () => {
    const rows = readSlice();
    const row = rows.find(target)!;
    row.payload = { ...row.payload, traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' };
    const report = verifyDumpStreaming(writeSlice(rows));
    expect(report.ok).toBe(false);
    expect(report.vault.failures[0]?.code).toBe('CHAIN_PAYLOAD_BINDING_MISMATCH');
  });
});

describe('a sealed agent signature that does not verify fails the dump', () => {
  // Synthetic, because a live entry cannot carry a bad agent signature without
  // also breaking its envelope signature: the vault key here is ours.
  function agentSigned(opts: { badSignature: boolean }) {
    const vaultKey = generateKey();
    const agent = generateKeyPairSync('ed25519');
    const jwk = agent.publicKey.export({ format: 'jwk' }) as AgentPublicKeyJwk;
    const contentHash = hash('sha256', '{"type":"example"}', 'hex');
    const signed = opts.badSignature ? hash('sha256', 'a different body', 'hex') : contentHash;
    const signature = nodeSign(null, Buffer.from(`${AGENT_SIGNATURE_CONTEXT}${signed}`), agent.privateKey).toString(
      'base64',
    );
    const entry = buildVaultEntry({
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
    const dump = {
      vaultEntries: [entry],
      vaultCheckpoints: [],
      signingKeys: [signingKeyDump(vaultKey)],
      keyStatements: [],
      orgAdminReads: [],
      orgAdminReadsCheckpoints: [],
    };
    return { dump, jwk, trustAnchors: [pinOf(vaultKey)] };
  }

  it('a good one verifies', () => {
    const { dump, jwk, trustAnchors } = agentSigned({ badSignature: false });
    const report = verifyDump(dump, { agentKeys: [jwk], trustAnchors });
    expect(report.ok).toBe(true);
    expect(report.vault.agentSignatures).toEqual({ present: 1, verified: 1 });
  });

  it('a bad one fails CHAIN_AGENT_SIGNATURE_INVALID only when its key is supplied', () => {
    const { dump, jwk, trustAnchors } = agentSigned({ badSignature: true });
    expect(verifyDump(dump, { trustAnchors }).ok).toBe(true);
    const report = verifyDump(dump, { agentKeys: [jwk], trustAnchors });
    expect(report.ok).toBe(false);
    expect(report.vault.optionalChecks.agent_signature).toBe('applied');
    expect(report.vault.agentSignatures).toEqual({ present: 1, verified: 0 });
    expect(report.vault.failures[0]?.code).toBe('CHAIN_AGENT_SIGNATURE_INVALID');
  });
});
