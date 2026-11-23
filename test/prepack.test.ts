import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

// `npm pack <folder>` runs the folder's own `prepack`, and an installed copy
// of this package is such a folder: no sources, no compiler. There `prepack`
// must leave the built `dist/` alone, since the build begins by deleting it.

function packageRoot(): string {
  let dir = import.meta.dirname;
  while (!existsSync(join(dir, 'package.json'))) dir = dirname(dir);
  return dir;
}

describe('prepack in an installed copy', () => {
  it('leaves dist/ in place where there are no sources to build from', () => {
    const installed = mkdtempSync(join(tmpdir(), 'installed-copy-'));
    try {
      writeFileSync(join(installed, 'package.json'), readFileSync(join(packageRoot(), 'package.json')));
      mkdirSync(join(installed, 'dist'));
      writeFileSync(join(installed, 'dist', 'index.js'), 'export {};\n');
      execSync('npm run prepack', { cwd: installed, stdio: 'pipe' });
      expect(existsSync(join(installed, 'dist', 'index.js'))).toBe(true);
    } finally {
      rmSync(installed, { recursive: true, force: true });
    }
  });

  it('is the build guarded on the sources being present', () => {
    const { scripts } = JSON.parse(readFileSync(join(packageRoot(), 'package.json'), 'utf8')) as { scripts: Record<string, string> };
    expect(scripts.prepack).toContain("existsSync('tsconfig.json')");
    expect(scripts.prepack).toContain('npm run build');
  });
});
