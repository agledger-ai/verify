#!/usr/bin/env node
/**
 * Pin the vendored conformance corpus. The corpus is the contract with the
 * engine: every fixture is real agledger-api engine output (tamper-transformed
 * by the generator), and it must change only through a deliberate regeneration
 * (agledger-api `pnpm generate:corpus`), never by hand.
 *
 * The lock records a sha256 per corpus file plus the manifest provenance
 * (which engine version and git SHA produced it). CI runs `--check`, so any
 * fixture edit that skips the lock rewrite fails loudly, naming exactly which
 * files drifted.
 *
 * Usage:
 *   node scripts/corpus-lock.mjs           rewrite the lock (after a regeneration)
 *   node scripts/corpus-lock.mjs --check   verify; exit 1 on drift (CI)
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(HERE, '..', 'testdata', 'conformance');
const LOCK_PATH = join(CORPUS_DIR, 'CORPUS-LOCK.json');
// Repo-side documentation, not engine output; SPEC.md survives regenerations.
const EXCLUDED = new Set(['CORPUS-LOCK.json']);

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

function computeLock() {
  const files = {};
  for (const p of walk(CORPUS_DIR).sort()) {
    const rel = relative(CORPUS_DIR, p).split(sep).join('/');
    if (EXCLUDED.has(rel)) continue;
    files[rel] = createHash('sha256').update(readFileSync(p)).digest('hex');
  }
  const manifest = JSON.parse(readFileSync(join(CORPUS_DIR, 'manifest-export.json'), 'utf8'));
  return { provenance: manifest.provenance ?? null, files };
}

const current = computeLock();

if (process.argv.includes('--check')) {
  let stored;
  try {
    stored = JSON.parse(readFileSync(LOCK_PATH, 'utf8'));
  } catch {
    console.error('CORPUS-LOCK.json missing or unreadable. Run: node scripts/corpus-lock.mjs');
    process.exit(1);
  }
  const drift = [];
  const storedFiles = stored.files ?? {};
  for (const [rel, hash] of Object.entries(current.files)) {
    if (storedFiles[rel] === undefined) drift.push(`added:    ${rel}`);
    else if (storedFiles[rel] !== hash) drift.push(`modified: ${rel}`);
  }
  for (const rel of Object.keys(storedFiles)) {
    if (current.files[rel] === undefined) drift.push(`removed:  ${rel}`);
  }
  if (drift.length > 0) {
    console.error('Conformance corpus drifted from CORPUS-LOCK.json:');
    for (const line of drift) console.error(`  ${line}`);
    console.error(
      'If this is a deliberate regeneration from agledger-api, rewrite the lock: '
      + 'node scripts/corpus-lock.mjs. Hand-edits to fixtures are never correct.',
    );
    process.exit(1);
  }
  console.log(
    `corpus lock ok: ${Object.keys(current.files).length} files, `
    + `engine ${current.provenance?.apiVersion ?? '?'} @ ${current.provenance?.apiGitSha ?? '?'}`,
  );
} else {
  writeFileSync(LOCK_PATH, `${JSON.stringify(current, null, 2)}\n`);
  console.log(
    `wrote ${relative(join(HERE, '..'), LOCK_PATH)}: ${Object.keys(current.files).length} files, `
    + `engine ${current.provenance?.apiVersion ?? '?'} @ ${current.provenance?.apiGitSha ?? '?'}`,
  );
}
