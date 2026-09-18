/**
 * R-267 / R-282 (CL-GAP-019, CL-GAP-069): eight `.d.ts.map` files were tracked
 * under `packages/runar-compiler/src/`.
 *
 * .gitignore already carried a block for this, with a comment recording that it
 * had happened once before ("A build run with a mis-set rootDir emits
 * .js/.js.map/.d.ts next to the .ts sources, and a `git add -A` then commits
 * them (happened once — 24 files)"). The block listed `*.js`, `*.js.map` and
 * `*.d.ts` — and not `*.d.ts.map`, so the same accident landed again through the
 * one hole in the rule that was written to prevent it.
 *
 * This test asks git what is tracked rather than trusting the ignore file, so a
 * ninth extension does not need a ninth line to be noticed.
 */

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Compiler output that must never be tracked inside a source tree. */
const BUILD_ARTIFACT = /\.(js|js\.map|d\.ts|d\.ts\.map|tsbuildinfo)$/;

describe('R-267/R-282: no build artifacts are tracked under packages/*/src', () => {
  it('holds for every tracked file', () => {
    const tracked = execFileSync('git', ['ls-files', 'packages'], {
      cwd: ROOT,
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean);

    expect(tracked.length, 'git ls-files returned nothing — the scan broke').toBeGreaterThan(100);

    const offenders = tracked.filter(
      (f) => /^packages\/[^/]+\/src\//.test(f) && BUILD_ARTIFACT.test(f),
    );

    expect(
      offenders,
      'these are tsc output committed next to the sources; add the extension to ' +
        'the .gitignore block and `git rm --cached` them',
    ).toEqual([]);
  });
});
