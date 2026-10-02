import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadDump } from '../src/loader.js';
import { verifyDump } from '../src/dump-verifier.js';
import { EXIT_CANNOT_VERIFY, EXIT_OK, runCli } from '../src/cli.js';
import {
  spkiSha256,
  verifyAuditExport,
  type RecordAuditExportInput,
  type VerifyExportOptions,
} from '@agledger/verify-core';
import type { Failure, FailureCode, VerifyReport } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = join(here, '..', 'testdata', 'conformance');

interface VectorOptions {
  keysFile?: string;
  requireKeyId?: string;
  requireSuppliedKeys?: boolean;
  /** `sha256:<hex>` pins the dump's key statements are walked from. */
  trustAnchors?: string[];
  /**
   * A JSON array of agent cert public keys (JWKs). Unmapped, a vector that
   * expects `CHAIN_AGENT_SIGNATURE_INVALID` runs with no agent keys, the check
   * reports `skipped_no_input`, the document passes, and the suite fails on a
   * vector that was never actually exercised.
   */
  agentKeysFile?: string;
}

interface SignatureCoverageSpec {
  signed: number;
  unsigned: number;
  skipped: number;
}

interface VectorSpec {
  file: string;
  kind: 'dump' | 'export';
  expect: 'pass' | 'fail';
  failureCode?: FailureCode;
  brokenAt?: number;
  options?: VectorOptions;
  expectSignatureCoverage?: SignatureCoverageSpec;
  note: string;
}

interface Manifest {
  vectors: VectorSpec[];
}

const manifest = JSON.parse(
  readFileSync(join(CONFORMANCE, 'manifest-dump.json'), 'utf-8'),
) as Manifest;

const dumpVectors = manifest.vectors.filter((v) => v.kind === 'dump');

const exportManifest = JSON.parse(
  readFileSync(join(CONFORMANCE, 'manifest-export.json'), 'utf-8'),
) as Manifest;

const exportVectors = exportManifest.vectors.filter((v) => v.kind === 'export');

function allFailures(report: VerifyReport): Failure[] {
  return [...report.vault.failures, ...report.orgAdminReads.failures];
}

/** Every code a dump report carries, the key-statement findings included. */
function allCodes(report: VerifyReport): FailureCode[] {
  return [...allFailures(report).map((f) => f.code), ...report.keyTrust.findings.map((f) => f.code)];
}

/**
 * The pin an operator hands an auditor: the Server's current key, the most
 * recently activated key some statement admits (a planted row has none). The
 * same rule verify-core's own dump runner uses.
 */
function currentPin(dir: string): string {
  const d = loadDump(join(CONFORMANCE, dir));
  const admitted = new Set(d.keyStatements.filter((st) => st.kind !== 'closure').map((st) => st.subject_key_id));
  const key = d.signingKeys
    .filter((k) => admitted.has(k.key_id))
    .sort((a, b) => Date.parse(b.activated_at ?? '') - Date.parse(a.activated_at ?? ''))[0];
  if (!key) throw new Error(`${dir}: no admitted key`);
  return `sha256:${spkiSha256(key.public_key)}`;
}

// An option the runner does not map runs the vector without it, and a renamed
// key (requireOutOfBandKeys became requireSuppliedKeys) then passes or fails for
// the wrong reason. Fail on any key VectorOptions does not name.
const MAPPED_OPTIONS = new Set(['keysFile', 'requireKeyId', 'requireSuppliedKeys', 'trustAnchors', 'agentKeysFile']);

describe('every manifest option is mapped', () => {
  it('names no option the runner ignores', () => {
    const used = new Set([...dumpVectors, ...exportVectors].flatMap((v) => Object.keys(v.options ?? {})));
    expect([...used].filter((k) => !MAPPED_OPTIONS.has(k))).toEqual([]);
  });
});

describe('DUMP conformance corpus (manifest-dump.json)', () => {
  it('manifest carries the full required failure-code set', () => {
    const codes = new Set(dumpVectors.map((v) => v.failureCode).filter(Boolean));
    for (const required of [
      'CHAIN_EMPTY',
      'CHECKPOINT_ROW_MISSING',
      'CHECKPOINT_HASH_MISMATCH',
      'CHAIN_PAYLOAD_BINDING_MISMATCH',
      'CHAIN_OIDC_ACTOR_MISMATCH',
      'CHAIN_KEY_EXPIRED',
      'TENANT_CHECKPOINT_ROOT_MISMATCH',
      'TENANT_CHECKPOINT_FORK',
    ] as const) {
      expect(codes.has(required), `missing required vector for ${required}`).toBe(true);
    }
    expect(dumpVectors.some((v) => v.expect === 'pass')).toBe(true);
  });

  // A vector without trustAnchors is verified with no walk, so the most a
  // pass can be is `unanchored`: nothing failed, and nothing was anchored.
  for (const vector of dumpVectors) {
    const anchors = vector.options?.trustAnchors;
    const pinned = anchors ? ` pinned on ${anchors.map((a) => a.slice(7, 23)).join(',')}` : '';
    it(`${vector.file}${pinned} -> ${vector.expect}${vector.failureCode ? ` (${vector.failureCode})` : ''}`, () => {
      const dumpDir = join(CONFORMANCE, vector.file);
      const report = verifyDump(loadDump(dumpDir), anchors ? { trustAnchors: anchors } : {});
      const codes = allCodes(report);

      if (vector.expect === 'pass') {
        expect(codes, 'expected pass').toEqual([]);
        expect(report.verdict).toBe(anchors ? 'trusted' : 'unanchored');
        return;
      }

      expect(report.verdict, `expected fail but verified clean`).toBe('failed');
      expect(codes, `expected ${vector.failureCode} in [${codes.join(', ')}]`).toContain(
        vector.failureCode,
      );
    });
  }

  it('CLI verifies the valid dump directory: unanchored unpinned, trusted pinned, exit 0 both', () => {
    const dir = join(CONFORMANCE, 'dump', 'valid');
    const unpinned = runCli([dir]);
    expect(unpinned.exitCode).toBe(EXIT_OK);
    expect(unpinned.stdout).toMatch(/^\[VERIFIED, NOT ANCHORED\]/);
    const pinned = runCli([dir, '--trust-anchor', currentPin('dump/valid')]);
    expect(pinned.exitCode).toBe(EXIT_OK);
    expect(pinned.stdout).toMatch(/^\[PASS\]/);
  });

  it('CLI exits nonzero on a failing dump directory and names the code', () => {
    const failing = dumpVectors.find((v) => v.failureCode === 'CHAIN_EMPTY');
    expect(failing).toBeDefined();
    const result = runCli([join(CONFORMANCE, failing!.file)]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('CHAIN_EMPTY');
  });
});

describe('DUMP corpus pinned on the Server\'s current key', () => {
  // Every pass vector whose registry columns are the engine's own, as
  // verify-core's dump runner holds them.
  it.each(['dump/valid', 'dump/valid-es256', 'dump/valid-identity', 'dump/valid-unsigned-history-then-signed'])(
    '%s verifies with every key anchored',
    (dir) => {
      const report = verifyDump(loadDump(join(CONFORMANCE, dir)), { trustAnchors: [currentPin(dir)] });
      expect(allCodes(report)).toEqual([]);
      expect(report.verdict).toBe('trusted');
      expect(report.keyTrust.order).toBe('written');
      expect(report.keyTrust.unanchoredKeyIds).toEqual([]);
    },
  );

  it('dump/chain-signing-key-unanchored pinned on the vault key fails the planted entry', () => {
    const dir = 'dump/chain-signing-key-unanchored';
    const report = verifyDump(loadDump(join(CONFORMANCE, dir)), { trustAnchors: [currentPin(dir)] });
    expect(allCodes(report)).toContain('CHAIN_SIGNING_KEY_UNANCHORED');
  });

  it('the key-window vectors sign the window they test, so pinned they give the verdict their manifest names', () => {
    // The engine regenerates these three by moving the window the vault key's
    // statements sign, not a vault_signing_keys column, so the walk from a pin
    // reaches the same verdict as the unpinned run and reports no drift.
    for (const dir of ['dump/valid-rotation-boundary', 'dump/chain-key-not-yet-active', 'dump/chain-key-expired']) {
      const vector = dumpVectors.find((v) => v.file === dir);
      expect(vector, dir).toBeDefined();
      const report = verifyDump(loadDump(join(CONFORMANCE, dir)), { trustAnchors: [currentPin(dir)] });
      const codes = allCodes(report);
      expect(codes, dir).not.toContain('CHAIN_KEY_WINDOW_DRIFT');
      if (vector!.expect === 'pass') expect(codes, dir).toEqual([]);
      else expect(codes, dir).toContain(vector!.failureCode);
    }
  });

  it('a distrusted key with no cutoff anchors nothing, so the dump signed under it fails', () => {
    const dir = 'dump/valid';
    const pin = currentPin(dir);
    const report = verifyDump(loadDump(join(CONFORMANCE, dir)), { trustAnchors: [pin], distrustedKeys: [pin] });
    expect(report.verdict).toBe('failed');
    expect(allCodes(report)).toContain('CHAIN_SIGNING_KEY_UNANCHORED');
  });
});

function loadKeys(options: VectorOptions | undefined): VerifyExportOptions {
  const out: VerifyExportOptions = {};
  if (options?.keysFile) {
    out.publicKeys = JSON.parse(
      readFileSync(join(CONFORMANCE, options.keysFile), 'utf-8'),
    ) as Record<string, string>;
  }
  if (options?.requireKeyId !== undefined) out.requireKeyId = options.requireKeyId;
  if (options?.requireSuppliedKeys !== undefined) {
    out.requireSuppliedKeys = options.requireSuppliedKeys;
  }
  if (options?.agentKeysFile) {
    out.agentKeys = JSON.parse(
      readFileSync(join(CONFORMANCE, options.agentKeysFile), 'utf-8'),
    ) as VerifyExportOptions['agentKeys'];
  }
  return out;
}

describe('EXPORT conformance corpus (manifest-export.json)', () => {
  it('manifest carries the full required export failure-code set', () => {
    const codes = new Set(exportVectors.map((v) => v.failureCode).filter(Boolean));
    for (const required of [
      'CHAIN_POSITION_GAP',
      'CHAIN_GENESIS_INVALID',
      'CHAIN_LINK_BROKEN',
      'CHAIN_HASH_MISMATCH',
      'CHAIN_MALFORMED_ENTRY',
      'CHAIN_COSE_DECODE_FAILED',
      'CHAIN_COSE_HEADER_MISMATCH',
      'CHAIN_SIGNATURE_INVALID',
      'CHAIN_SIGNATURE_MISSING_KEY',
      'CHAIN_KEY_POLICY_VIOLATION',
      'CHAIN_PAYLOAD_BINDING_MISMATCH',
      'CHAIN_EMPTY',
      'UNSUPPORTED_FORMAT',
    ] as const) {
      expect(codes.has(required), `missing required export vector for ${required}`).toBe(true);
    }
    expect(exportVectors.some((v) => v.expect === 'pass')).toBe(true);
  });

  exportVectors.forEach((vector, idx) => {
    const label = `[${idx}] ${vector.file} -> ${vector.expect}${vector.failureCode ? ` (${vector.failureCode})` : ''}`;
    it(label, () => {
      const exportDoc = JSON.parse(
        readFileSync(join(CONFORMANCE, vector.file), 'utf-8'),
      ) as RecordAuditExportInput;
      const result = verifyAuditExport(exportDoc, loadKeys(vector.options));

      if (vector.expect === 'pass') {
        expect(
          result.valid,
          `expected pass but broke at ${JSON.stringify(result.brokenAt)}`,
        ).toBe(true);
        if (vector.expectSignatureCoverage) {
          expect(result.signatureCoverage.signed).toBe(vector.expectSignatureCoverage.signed);
          expect(result.signatureCoverage.unsigned).toBe(vector.expectSignatureCoverage.unsigned);
          expect(result.signatureCoverage.skipped).toBe(vector.expectSignatureCoverage.skipped);
        }
        return;
      }

      expect(result.valid, `expected fail but verified clean`).toBe(false);
      expect(result.brokenAt, `expected a brokenAt for a failing vector`).toBeDefined();
      expect(
        result.brokenAt?.code,
        `expected ${vector.failureCode}, got ${result.brokenAt?.code}`,
      ).toBe(vector.failureCode);
      if (vector.brokenAt !== undefined) {
        expect(
          result.brokenAt?.position,
          `expected break at position ${vector.brokenAt}, got ${result.brokenAt?.position}`,
        ).toBe(vector.brokenAt);
      }
    });
  });

  it('CLI verifies a valid export file and exits 0', () => {
    const valid = exportVectors.find((v) => v.expect === 'pass' && !v.options?.requireKeyId);
    expect(valid).toBeDefined();
    const unpinned = runCli([join(CONFORMANCE, valid!.file), '--report-format=json']);
    expect(unpinned.exitCode).toBe(EXIT_OK);
    expect(JSON.parse(unpinned.stdout)).toMatchObject({ valid: true, verdict: 'unanchored', keyTrust: { status: 'no_anchor' } });
    const anchoredFrom = (JSON.parse(readFileSync(join(CONFORMANCE, valid!.file), 'utf-8')) as RecordAuditExportInput)
      .exportMetadata.anchoredFrom!;
    const pinned = runCli([join(CONFORMANCE, valid!.file), '--report-format=json', '--trust-anchor', anchoredFrom]);
    expect(pinned.exitCode).toBe(EXIT_OK);
    expect(JSON.parse(pinned.stdout)).toMatchObject({ valid: true, verdict: 'trusted', keyTrust: { status: 'walked', anchoredFromPinned: true } });
  });

  it('CLI exits nonzero on a failing export file and names the code', () => {
    const failing = exportVectors.find((v) => v.failureCode === 'CHAIN_EMPTY');
    expect(failing).toBeDefined();
    const result = runCli([join(CONFORMANCE, failing!.file), '--report-format=json']);
    expect(result.exitCode).not.toBe(0);
    const parsed = JSON.parse(result.stdout) as { brokenAt?: { code: string } };
    expect(parsed.brokenAt?.code).toBe('CHAIN_EMPTY');
  });
});

describe('CLI auto-detect: export-file path branches to verify-core', () => {
  let dir: string;

  it('detects an /audit-export JSON file and runs the export verifier', () => {
    dir = mkdtempSync(join(tmpdir(), 'agledger-verify-export-'));
    try {
      // A minimal export with an unsupported format version forces a
      // deterministic FAIL through the export path without needing signed
      // bytes; the point here is that the file-detection branch fired.
      const exportDoc = {
        exportMetadata: {
          recordId: 'rec-1',
          exportFormatVersion: '1.0',
          canonicalization: 'RFC8949-CDE',
        },
        entries: [],
      };
      const file = join(dir, 'audit-export.json');
      writeFileSync(file, JSON.stringify(exportDoc));
      const result = runCli([file, '--report-format=json']);
      expect(result.exitCode).not.toBe(0);
      const parsed = JSON.parse(result.stdout) as { recordId: string; brokenAt?: { code: string } };
      expect(parsed.recordId).toBe('rec-1');
      expect(parsed.brokenAt?.code).toBe('UNSUPPORTED_FORMAT');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a JSON file that is neither a dump dir nor an export document', () => {
    dir = mkdtempSync(join(tmpdir(), 'agledger-verify-bad-'));
    try {
      const file = join(dir, 'random.json');
      writeFileSync(file, JSON.stringify({ hello: 'world' }));
      const result = runCli([file]);
      expect(result.exitCode).toBe(EXIT_CANNOT_VERIFY);
      expect(result.stderr).toContain('neither a dump directory nor an /audit-export');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
