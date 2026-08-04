#!/usr/bin/env node
/**
 * Reports lockfile lag that `npm install` will not fix.
 *
 * `npm install` honours the lockfile, so a dependency can sit at an old version
 * indefinitely even when package.json's own range already permits a newer one.
 * Nothing surfaces this: the install prints "up to date" and is telling the
 * truth about the lockfile while being misleading about the ranges. That is how
 * this repo published against a lockfile a maintainer believed was current.
 * `npm update` is what moves in-range dependencies.
 *
 * Two categories, and only one of them is a problem:
 *
 *   current !== wanted   in-range lag. package.json already allows it, so
 *                        taking it is never a policy decision. Exit 1.
 *   wanted !== latest    out-of-range. A newer major exists that our range
 *                        excludes. Often deliberate (see .github/dependabot.yml
 *                        for the @types/node hold). Reported, never fatal.
 *
 * Run `npm run deps:refresh` to fix the first category.
 */

import { execFileSync } from 'node:child_process';

/** `npm outdated` exits 1 when anything is outdated, which is not an error here. */
function readOutdated() {
  let raw;
  try {
    raw = execFileSync('npm', ['outdated', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  } catch (err) {
    if (typeof err.stdout !== 'string') throw err;
    raw = err.stdout;
  }
  if (!raw.trim()) return {};
  return JSON.parse(raw);
}

/** npm reports an array when one dependency resolves at several paths. */
function entriesFor(name, value) {
  return (Array.isArray(value) ? value : [value]).map(v => ({ name, ...v }));
}

const outdated = readOutdated();
const all = Object.entries(outdated).flatMap(([name, value]) => entriesFor(name, value));

const inRange = all.filter(d => d.current && d.wanted && d.current !== d.wanted);
const outOfRange = all.filter(d => d.wanted && d.latest && d.wanted !== d.latest);

if (outOfRange.length > 0) {
  console.log('Out of range (newer version exists, our declared range excludes it):');
  for (const d of outOfRange) {
    console.log(`  ${d.name}  ${d.wanted} -> ${d.latest}`);
  }
  console.log('  Taking these is a deliberate call. See .github/dependabot.yml for standing holds.\n');
}

if (inRange.length === 0) {
  console.log('No in-range lockfile lag. Every dependency is at the newest version its range allows.');
  process.exit(0);
}

console.error('In-range lockfile lag (package.json already allows these; npm install will NOT take them):');
for (const d of inRange) {
  console.error(`  ${d.name}  ${d.current} -> ${d.wanted}`);
}
console.error('\nRun: npm run deps:refresh');
process.exit(1);
