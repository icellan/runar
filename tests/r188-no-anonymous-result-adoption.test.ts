/**
 * R-188 (CL-BUG-124): `peekAtDepth(i) ?? bindingName` silently adopts an
 * anonymous result slot under the `if`'s binding name; two such slots would
 * produce duplicate names and `findDepth` would resolve every reference to the
 * shallower one. "Exactly the shape of fallback that hid the 2026-08 miscompile
 * family."
 *
 * Confirmed at `05-stack-lower.ts`, in the `#99 Bug 1` reconcile that adopts
 * N>=2 branch results.
 *
 * UNREACHABLE TODAY, AND THE REASON IS ORDERING, not luck:
 * `drainBranchPrivateResidue` runs on each arm before this reconcile and
 * removes every unnamed slot, so each result is named by the time it is read.
 * Measured rather than assumed — the site was instrumented and all 176 in-repo
 * `.runar.ts` contracts compiled in both fold modes (352 compilations) without
 * it firing once, and two hand-built contracts that put `substr` residue and two
 * state writes in the same arm did not reach it either.
 *
 * WHAT THIS TEST CAN AND CANNOT DO. Because the path is unreachable from valid
 * source, there is no contract that exercises the refusal, so this is a
 * source-shape guard plus a regression sweep rather than a behavioural test.
 * Saying that plainly matters more than dressing it up: the behavioural evidence
 * is the 352-compilation sweep, which is reproduced here as the second case.
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PASS = 'packages/runar-compiler/src/passes/05-stack-lower.ts';
const source = readFileSync(join(ROOT, PASS), 'utf-8');

/**
 * R-188-FU: this used to enumerate with `find`, which has no concept of
 * "tracked" — it picks up conformance/.tmp/parseonly-*.runar.ts scratch
 * files that concurrent conformance runs write and then delete, and (when
 * run from a checkout that hosts nested .worktrees/ copies) every other
 * worktree's contracts too. `git ls-files` only ever returns files the repo
 * actually tracks, so it sees neither.
 */
function listRunarTsFiles(): string[] {
  return execSync("git ls-files -- '*.runar.ts'", { cwd: ROOT, encoding: 'utf-8' })
    .trim()
    .split('\n')
    .filter(Boolean);
}

describe('R-188: an anonymous branch result is refused, not renamed', () => {
  it('the silent fallback is gone', () => {
    // The literal shape the finding names. A `??` default here is what turns a
    // broken invariant into a duplicate stack-map name.
    expect(
      source,
      'the reconcile still defaults an anonymous slot to the binding name',
    ).not.toMatch(/peekAtDepth\([^)]*\)\s*\?\?\s*bindingName/);
  });

  it('and the site refuses instead', () => {
    expect(source).toMatch(/result slot \$\{i\} of \$\{resultCount\} is/);
  });

  it('the enumeration excludes an untracked scratch .runar.ts file', () => {
    // conformance/runner/runner.ts writes exactly this shape of file
    // (conformance/.tmp/parseonly-ts-<pid>-<rand>-<name>.runar.ts) while a
    // --parser-only run is in flight, then deletes it. If the sweep below
    // enumerates with `find`, it can observe that file mid-flight and then
    // fail with ENOENT once the owning run deletes it out from under a
    // concurrent `readFileSync` (checkpoint-12/vitest-all.log ~line 3839).
    // `git ls-files` never returns it, because it is never `git add`ed.
    const tmpDir = join(ROOT, 'conformance', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const marker = `parseonly-ts-${process.pid}-${Date.now()}-R188FU.runar.ts`;
    const tmpFile = join(tmpDir, marker);
    writeFileSync(tmpFile, '// scratch file a concurrent conformance run would write', 'utf-8');
    try {
      expect(existsSync(tmpFile), 'setup: the scratch file was not actually written').toBe(true);
      const files = listRunarTsFiles();
      expect(
        files.some((f) => f.endsWith(marker)),
        'the enumeration picked up an untracked scratch file under conformance/.tmp',
      ).toBe(false);
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it('every in-repo contract still compiles, in both fold modes', () => {
    // The regression check that matters: turning a fallback into a throw is only
    // safe if nothing reaches it. This is the sweep the measurement above used.
    const files = listRunarTsFiles();
    expect(files.length, 'the sweep found no contracts; it would pass vacuously').toBeGreaterThan(
      100,
    );

    const failures: string[] = [];
    for (const f of files) {
      const src = readFileSync(join(ROOT, f), 'utf-8');
      const name = f.split('/').pop()!;
      for (const disableConstantFolding of [true, false]) {
        try {
          compile(src, { fileName: name, disableConstantFolding });
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          // Only this refusal is a regression; a contract that already failed
          // to compile for its own reasons is not this test's business.
          if (/is\s+anonymous/.test(msg)) failures.push(`${f}: ${msg.slice(0, 160)}`);
        }
      }
    }
    expect(failures, 'the new refusal fired on a contract that used to compile').toEqual([]);
  }, 300_000);
});
