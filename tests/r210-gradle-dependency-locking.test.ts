/**
 * R-210 (CL-GAP-050): only 2 of 7 Gradle projects lock their dependencies, so
 * CI's osv-scanner can only scan those two.
 *
 * Measured before the fix:
 *
 *     compilers/java                              locked + scanned
 *     packages/runar-java                         locked + scanned
 *     integration/java                            NOT locked
 *     examples/java                               NOT locked
 *     examples/end2end-example/java               NOT locked
 *     conformance/anf-interpreter/drivers/java    NOT locked
 *     conformance/sdk-output/tools/java-driver    NOT locked
 *
 * and `dependency-audit.yml` described the repo as though the first two were
 * all of it: "Both Gradle projects enable dependencyLocking and commit
 * gradle.lockfile."
 *
 * The practical exposure was narrower than 5-of-7 suggests — the unscanned five
 * add JUnit on top of a `runar-java` graph that IS scanned — but the gap is
 * real: a third-party dependency added to any of those five would have been
 * invisible to the audit, and nothing said so.
 *
 * This test states the invariant rather than the current count, so a Gradle
 * project added tomorrow is caught the day it lands: every `build.gradle.kts`
 * enables `dependencyLocking`, commits a `gradle.lockfile` next to it, and is
 * named in an osv-scanner step.
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { readFileSync, existsSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Every Gradle project in the repo, as build-file paths relative to ROOT.
 *
 * R-210-FU: this used to enumerate with `find`, which has no concept of
 * "tracked" — run from a checkout that hosts nested .worktrees/ copies (each
 * a full repo clone, gitignored but not excluded by `find`), it returns
 * every other worktree's build.gradle.kts too, which then fails "each one
 * enables dependencyLocking" / "each lockfile is named" for paths this repo
 * does not actually contain. `git ls-files` only ever returns files this
 * repo tracks, so nested worktrees and any other scratch build.gradle.kts
 * (e.g. one a test writes under conformance/.tmp) are both invisible to it.
 */
function gradleProjects(): string[] {
  const out = execSync("git ls-files -- '*build.gradle.kts'", { cwd: ROOT, encoding: 'utf-8' });
  return out
    .trim()
    .split('\n')
    .filter(Boolean)
    .sort();
}

const AUDIT = 'github/workflows/dependency-audit.yml';
const auditYml = readFileSync(join(ROOT, '.github/workflows/dependency-audit.yml'), 'utf-8');

describe('R-210: every Gradle project is locked and scanned', () => {
  it('the enumeration excludes an untracked scratch build.gradle.kts', () => {
    // A nested .worktrees/ checkout (gitignored, but still on disk) or a test
    // scratch file under conformance/.tmp both produce an untracked
    // build.gradle.kts somewhere under ROOT. If the enumeration used `find`,
    // it would list that path too, and the later assertions would then fail
    // for a project this repo does not actually contain.
    const tmpDir = join(ROOT, 'conformance', '.tmp');
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });
    const scratchDir = join(tmpDir, 'r210fu-scratch-project');
    if (!existsSync(scratchDir)) mkdirSync(scratchDir, { recursive: true });
    const scratchFile = join(scratchDir, 'build.gradle.kts');
    writeFileSync(scratchFile, '// untracked scratch gradle project', 'utf-8');
    try {
      expect(existsSync(scratchFile), 'setup: the scratch file was not actually written').toBe(
        true,
      );
      const relative = 'conformance/.tmp/r210fu-scratch-project/build.gradle.kts';
      expect(
        gradleProjects(),
        'the enumeration picked up an untracked scratch build.gradle.kts',
      ).not.toContain(relative);
    } finally {
      unlinkSync(scratchFile);
    }
  });

  it('finds the Gradle projects at all', () => {
    // Guards against the find silently matching nothing and the whole file
    // passing vacuously.
    expect(gradleProjects().length).toBeGreaterThanOrEqual(7);
  });

  it('each one enables dependencyLocking', () => {
    const unlocked = gradleProjects().filter(
      (p) => !readFileSync(join(ROOT, p), 'utf-8').includes('dependencyLocking'),
    );
    expect(unlocked, 'these Gradle projects do not lock their dependency graph').toEqual([]);
  });

  it('each one commits a gradle.lockfile beside it', () => {
    const missing = gradleProjects().filter(
      (p) => !existsSync(join(ROOT, dirname(p), 'gradle.lockfile')),
    );
    expect(
      missing,
      'locking is declared but no lock state is committed, so osv-scanner has nothing to read',
    ).toEqual([]);
  });

  it('each lockfile is named in an osv-scanner step', () => {
    const unscanned = gradleProjects()
      .map((p) => join(dirname(p), 'gradle.lockfile'))
      .filter((lock) => !auditYml.includes(lock));
    expect(
      unscanned,
      `these lockfiles exist but ${AUDIT} never scans them`,
    ).toEqual([]);
  });

  it('the workflow does not still describe the repo as having two', () => {
    // The comment said "Both Gradle projects enable dependencyLocking", which
    // was the shape of the gap: the count was written down as if complete.
    expect(
      auditYml,
      'dependency-audit.yml still says "Both Gradle projects"',
    ).not.toMatch(/Both Gradle projects/);
  });
});
