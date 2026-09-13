/**
 * R-276 (CL-GAP-054): two packaging gaps in the Java tier.
 *
 * 1. `conformance/anf-interpreter/drivers/java/build/` is not in `.gitignore`,
 *    while the other six Gradle projects' build directories are. Running that
 *    driver leaves a tree of class files staged-able, and the first person to
 *    `git add -A` commits compiler output.
 *
 * 2. No Java manifest declares a license. The repo is MIT and every other
 *    ecosystem says so in its own metadata — package.json `license`,
 *    Cargo.toml, the gemspec, pyproject. A jar that travels without it is the
 *    one artifact a consumer's license scanner cannot classify.
 *
 * Neither is a correctness bug, and neither is caught by any suite: the first
 * shows up as an accident in someone's commit, the second in someone else's
 * compliance review. The test derives both from the tree, so a new Gradle
 * project inherits the requirement instead of being remembered.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Every directory in the repo holding a Gradle build script. */
function gradleProjects(dir = ROOT, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'build') continue;
    const p = join(dir, entry.name);
    if (entry.isDirectory()) gradleProjects(p, out);
    else if (entry.name === 'build.gradle.kts') out.push(dir);
  }
  return out;
}

/** Gradle scripts that configure a `jar` manifest — the artifacts that ship. */
function jarManifestScripts(): string[] {
  return gradleProjects()
    .map((d) => join(d, 'build.gradle.kts'))
    .filter((f) => /tasks\.named<Jar>\("jar"\)/.test(readFileSync(f, 'utf8')));
}

describe('R-276: Java packaging metadata', () => {
  it('the project scan is not vacuous', () => {
    expect(gradleProjects().length).toBeGreaterThanOrEqual(7);
  });

  it("every Gradle project's build/ directory is git-ignored", () => {
    const notIgnored = gradleProjects().filter((d) => {
      const rel = `${relative(ROOT, d)}/build/`;
      const res = spawnSync('git', ['check-ignore', '-q', rel], { cwd: ROOT });
      return res.status !== 0;
    });
    expect(
      notIgnored.map((d) => `${relative(ROOT, d)}/build/`),
      'Gradle output directories that git would offer to commit',
    ).toEqual([]);
  });

  it('every jar manifest declares the license', () => {
    const scripts = jarManifestScripts();
    expect(scripts.length, 'no jar manifests found — the scan broke').toBeGreaterThan(0);

    const missing = scripts
      .filter((f) => !/Bundle-License|Implementation-License|"License"/.test(readFileSync(f, 'utf8')))
      .map((f) => relative(ROOT, f));
    expect(missing, 'jar manifests with no license attribute').toEqual([]);
  });

  it('the license they declare is the repo license', () => {
    const repoLicense = readFileSync(join(ROOT, 'LICENSE'), 'utf8').split('\n')[0]!.trim();
    expect(repoLicense).toBe('MIT License');
    for (const f of jarManifestScripts()) {
      expect(readFileSync(f, 'utf8'), `${relative(ROOT, f)} names a different license`).toMatch(
        /"MIT"/,
      );
    }
  });
});
