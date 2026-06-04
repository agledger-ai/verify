import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadDump } from '../src/loader.js';
import { verifyDump } from '../src/dump-verifier.js';
import { runCli } from '../src/cli.js';
import {
  verifyAuditExport,
  type RecordAuditExportInput,
  type VerifyExportOptions,
} from '@agledger/verify-core';
import type { Failure, FailureCode } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = join(here, '..', 'testdata', 'conformance');

interface VectorOptions {
  keysFile?: string;
  requireKeyId?: string;
  requireOutOfBandKeys?: boolean;
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

function allFailures(report: ReturnType<typeof verifyDump>): Failure[] {
  return [...report.vault.failures, ...report.orgAdminReads.failures];
}

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

  for (const vector of dumpVectors) {
    it(`${vector.file} -> ${vector.expect}${vector.failureCode ? ` (${vector.failureCode})` : ''}`, () => {
      const dumpDir = join(CONFORMANCE, vector.file);
      const report = verifyDump(loadDump(dumpDir));

      if (vector.expect === 'pass') {
        expect(report.ok, `expected pass but got failures: ${JSON.stringify(allFailures(report))}`).toBe(true);
        return;
      }

      expect(report.ok, `expected fail but verified clean`).toBe(false);
      const codes = allFailures(report).map((f) => f.code);
      expect(codes, `expected ${vector.failureCode} in [${codes.join(', ')}]`).toContain(
        vector.failureCode,
      );
    });
  }

  it('CLI verifies the valid dump directory and exits 0', () => {
    const valid = dumpVectors.find((v) => v.expect === 'pass');
    expect(valid).toBeDefined();
    const result = runCli([join(CONFORMANCE, valid!.file)]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/^\[PASS\]/);
  });

  it('CLI exits nonzero on a failing dump directory and names the code', () => {
    const failing = dumpVectors.find((v) => v.failureCode === 'CHAIN_EMPTY');
    expect(failing).toBeDefined();
    const result = runCli([join(CONFORMANCE, failing!.file)]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('CHAIN_EMPTY');
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
  if (options?.requireOutOfBandKeys !== undefined) {
    out.requireOutOfBandKeys = options.requireOutOfBandKeys;
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
    const result = runCli([join(CONFORMANCE, valid!.file), '--report-format=json']);
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout) as { valid: boolean };
    expect(parsed.valid).toBe(true);
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

describe('CLI auto-detect — export-file path branches to verify-core', () => {
  let dir: string;

  it('detects an /audit-export JSON file and runs the export verifier', () => {
    dir = mkdtempSync(join(tmpdir(), 'agledger-verify-export-'));
    try {
      // A minimal export with an unsupported format version forces a
      // deterministic FAIL through the export path without needing signed
      // bytes — the point here is that the file-detection branch fired.
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
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('neither a dump directory nor an /audit-export');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
