/**
 * Code quality lint tests — catches AI-generated code patterns.
 *
 * Repo-scoped copy (@agledger/verify is its own source-of-truth repo). Mirrors
 * the checks the AGLedger monorepo enforced, narrowed to this package's `src`.
 * Run with `npm test`.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { describe, it, expect } from 'vitest';

const ROOT = join(import.meta.dirname, '..');

/** Source directories to scan (relative to repo root). */
const SOURCE_DIRS = ['src'];

/** Collect all source files recursively. */
function collectFiles(dir: string, exts: string[]): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === 'node_modules' || entry === 'dist' || entry === '__tests__') continue;
    const stat = statSync(full);
    if (stat.isDirectory()) {
      results.push(...collectFiles(full, exts));
    } else if (exts.includes(extname(full))) {
      results.push(full);
    }
  }
  return results;
}

function allTsFiles(): string[] {
  return SOURCE_DIRS.flatMap((d) => collectFiles(join(ROOT, d), ['.ts']));
}

function relPath(file: string): string {
  return relative(ROOT, file);
}

describe('no emoji in source files', () => {
  const emojiPattern =
    /[\u{1F300}-\u{1F9FF}\u{2700}-\u{27BF}\u{2600}-\u{26FF}\u{2300}-\u{23FF}\u{2B50}\u{2B55}\u{2705}\u{274C}\u{274E}\u{2728}\u{2734}\u{2744}\u{2747}\u{2757}\u{2763}\u{2764}\u{FE0F}\u{200D}\u{20E3}\u{E0020}-\u{E007F}]|[✓✅⚡⏳📋📊❌⚠️✨🔥💡🚀🎉]/gu;

  it('should not contain emoji characters', () => {
    const violations: string[] = [];
    for (const file of allTsFiles()) {
      const content = readFileSync(file, 'utf8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].match(emojiPattern);
        if (matches) {
          violations.push(`${relPath(file)}:${i + 1}  found: ${matches.join(', ')}`);
        }
      }
    }
    expect(violations, `Emoji found in source files:\n${violations.join('\n')}`).toHaveLength(0);
  });
});

describe('no decorative section dividers', () => {
  const dividerPattern = /^\s*\/\/\s*[-=═─━]{10,}\s*$/;

  it('should not contain // --- or // === decorative dividers', () => {
    const violations: string[] = [];
    for (const file of allTsFiles()) {
      const lines = readFileSync(file, 'utf8').split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (dividerPattern.test(lines[i])) {
          violations.push(`${relPath(file)}:${i + 1}  ${lines[i].trim()}`);
        }
      }
    }
    expect(violations, `Section dividers found:\n${violations.join('\n')}`).toHaveLength(0);
  });
});

describe('no per-file copyright boilerplate', () => {
  const copyrightPattern = /Patent Pending|Copyright 20\d{2} AGLedger LLC\. All rights reserved/;

  it('should not have copyright headers in source files (use LICENSE file)', () => {
    const violations: string[] = [];
    for (const file of allTsFiles()) {
      const head = readFileSync(file, 'utf8').split('\n').slice(0, 10).join('\n');
      if (copyrightPattern.test(head)) {
        violations.push(relPath(file));
      }
    }
    expect(violations, `Per-file copyright found:\n${violations.join('\n')}`).toHaveLength(0);
  });
});

describe('publishable package cleans dist before building', () => {
  it('build wipes dist/ (prebuild rm -rf dist) so no orphans ship', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      scripts?: Record<string, string>;
    };
    const scripts = pkg.scripts ?? {};
    const cleansDist = (s: string | undefined): boolean =>
      s !== undefined && /\b(rm -rf|rimraf)\b[^&|]*\bdist\b/.test(s);
    expect(
      cleansDist(scripts.prebuild) || cleansDist(scripts.build),
      'build does not wipe dist/ first (add "prebuild": "rm -rf dist")',
    ).toBe(true);
  });
});

describe('offline verifier makes no network access', () => {
  // The verifier's entire value is producing a correct verdict even if the
  // engine that produced the records is compromised. A verifier that can reach
  // the network could be steered to "phone home" for a verdict — so this package
  // must import nothing network-capable and never call fetch.
  const networkImport =
    /\b(?:import|require)\b[^\n]*['"](?:node:)?(?:http2?|https|net|tls|dgram|dns)['"]/;
  const fetchCall = /\bfetch\s*\(/;

  it('imports no http/net modules and calls no fetch', () => {
    const violations: string[] = [];
    for (const dir of SOURCE_DIRS) {
      for (const file of collectFiles(join(ROOT, dir), ['.ts'])) {
        const lines = readFileSync(file, 'utf8').split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (networkImport.test(lines[i]) || fetchCall.test(lines[i])) {
            violations.push(`${relPath(file)}:${i + 1}  ${lines[i].trim()}`);
          }
        }
      }
    }
    expect(
      violations,
      `Network access in an offline verifier package:\n${violations.join('\n')}`,
    ).toHaveLength(0);
  });
});

describe('bounded em-dash density in shipped markdown', () => {
  // Heavy em-dash usage reads as machine-generated. Cap the density in every
  // shipped Markdown doc so prose stays at a natural human level.
  const MAX_EM_DASHES = 4;

  function collectMarkdown(dir: string): string[] {
    const results: string[] = [];
    for (const entry of readdirSync(dir)) {
      if (
        entry === 'node_modules' ||
        entry === 'dist' ||
        entry === 'build' ||
        entry === '.git'
      ) {
        continue;
      }
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        results.push(...collectMarkdown(full));
      } else if (extname(full) === '.md' && entry !== 'CHANGELOG.md') {
        results.push(full);
      }
    }
    return results;
  }

  it(`has at most ${MAX_EM_DASHES} em-dashes (U+2014) per file`, () => {
    const violations: string[] = [];
    for (const file of collectMarkdown(ROOT)) {
      const count = (readFileSync(file, 'utf8').match(/—/g) ?? []).length;
      if (count > MAX_EM_DASHES) {
        violations.push(`${relPath(file)}  ${count} em-dashes (max ${MAX_EM_DASHES})`);
      }
    }
    expect(
      violations,
      `Markdown files exceeding the em-dash cap:\n${violations.join('\n')}`,
    ).toHaveLength(0);
  });
});
