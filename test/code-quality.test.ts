/**
 * Source hygiene checks over this package's own code.
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

describe('no truthiness tests on signing-key ids', () => {
  // null is the system-wide unsigned-mode marker for these fields. A
  // truthiness test treats a tampered "" like null and skips the signature
  // check (fail-open); the empty string must instead fall through to key
  // resolution and fail as an unknown key. Six instances of this class
  // shipped in the verifier wave before the sweep; this pins it at zero.
  // Legal spellings: `=== null`, `!== null`, and `??`.
  const TRUTHY_PATTERNS = [
    /if \((?:[\w.]+\.)?(?:signingKeyId|signing_key_id)\)/,
    /if \(!(?:[\w.]+\.)?(?:signingKeyId|signing_key_id)\)/,
    /(?:[\w.]+\.)?(?:signingKeyId|signing_key_id)\s*(?:\?\s|&&|\|\|(?!\|))/,
    /!(?:[\w.]+\.)?(?:signingKeyId|signing_key_id)\b/,
  ];

  it('src compares signing-key ids against null explicitly', () => {
    const offenders: string[] = [];
    for (const file of allTsFiles()) {
      const lines = readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, i) => {
        if (line.includes('!== null') || line.includes('=== null')) return;
        if (TRUTHY_PATTERNS.some(re => re.test(line))) {
          offenders.push(`${relPath(file)}:${i + 1}: ${line.trim()}`);
        }
      });
    }
    expect(offenders).toEqual([]);
  });
});

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
  // the network could be steered to "phone home" for a verdict, so this package
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

describe('no em dashes', () => {
  // House style is plain punctuation, and it applies to shipped prose rather
  // than just to docs: `dist/*.d.ts` is what a consumer's editor renders on
  // hover, and a published tarball cannot be edited afterwards. Written as an
  // escape so the pattern does not match its own source.
  const EM_DASH = /\u2014/;

  // `dist`/`build`/`coverage` are output and `CHANGELOG.md` is history.
  // `testdata` is generated upstream and digest-pinned by CORPUS-LOCK.json,
  // so changes there have to be made at the generator.
  const SKIP = new Set([
    'node_modules',
    'dist',
    'build',
    'coverage',
    '.git',
    '.claude',
    'testdata',
  ]);

  function walk(dir: string, keep: (entry: string) => boolean): string[] {
    const results: string[] = [];
    for (const entry of readdirSync(dir)) {
      if (SKIP.has(entry)) continue;
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) results.push(...walk(full, keep));
      else if (keep(entry)) results.push(full);
    }
    return results;
  }

  function offenders(files: string[]): string[] {
    const found: string[] = [];
    for (const file of files) {
      readFileSync(file, 'utf8')
        .split('\n')
        .forEach((line, i) => {
          if (EM_DASH.test(line)) found.push(`${relPath(file)}:${i + 1}  ${line.trim()}`);
        });
    }
    return found;
  }

  it('markdown, workflows and config carry none', () => {
    // `.github/workflows` and `package.json` ship in the repo and the tarball
    // respectively, and both carried dashes the markdown-only gate never saw.
    const PROSE_EXT = new Set(['.md', '.yml', '.yaml']);
    const found = offenders(
      walk(ROOT, e => (PROSE_EXT.has(extname(e)) || e === 'package.json') && e !== 'CHANGELOG.md'),
    );
    expect(found, `Em dashes in markdown/workflows/config:\n${found.join('\n')}`).toHaveLength(0);
  });

  it('source and tests carry none', () => {
    // Broader than SOURCE_DIRS: `collectFiles` skips `__tests__`, and a test
    // file's comments are source we ship in the repo just the same.
    const dirs = readdirSync(ROOT).filter(e => e === 'src' || e === 'test' || e === 'tests');
    const found = offenders(dirs.flatMap(d => walk(join(ROOT, d), e => extname(e) === '.ts')));
    expect(found, `Em dashes in source:\n${found.join('\n')}`).toHaveLength(0);
  });
});

describe('published tarball carries no dangling source-map references', () => {
  // `files` excludes dist/**/*.map because the maps point at ../src/*.ts with no
  // sourcesContent and src/ is not in the tarball, so they resolve to nothing.
  // Excluding the file is only half the change: tsc still appends a
  // `//# sourceMappingURL=` comment to every .js and .d.ts, which then points at
  // a map the tarball does not contain (agents#114). Turn the emit off instead.
  it('does not emit maps that "files" excludes', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      files?: string[];
    };
    const excludesMaps = (pkg.files ?? []).some((f) => f.startsWith('!') && f.endsWith('.map'));

    const tsconfig = JSON.parse(readFileSync(join(ROOT, 'tsconfig.json'), 'utf8')) as {
      compilerOptions?: { sourceMap?: boolean; declarationMap?: boolean };
    };
    const opts = tsconfig.compilerOptions ?? {};
    const emitting = (['sourceMap', 'declarationMap'] as const).filter((k) => opts[k] === true);

    expect(
      excludesMaps ? emitting : [],
      `tsconfig turns on ${emitting.join(' + ')} while package.json "files" excludes *.map, ` +
        'so every emitted file would reference a map that never ships. ' +
        'Either drop the "files" exclusion or turn the emit off.',
    ).toHaveLength(0);
  });
});
