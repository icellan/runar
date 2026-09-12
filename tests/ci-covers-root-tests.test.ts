/**
 * R-110 — the repo-root `tests/` directory was never executed by CI or by any
 * script chain.
 *
 * `package.json`'s `test` is `turbo run test`, which runs workspace packages;
 * root `tests/` is not a workspace member, so it is not one of them. `test:ci`
 * chains `test:all` -> conformance / examples / e2e / wallet-client, and none
 * of those reaches it either. In `.github/workflows/ci.yml` every
 * `npx vitest run` is path-scoped, and only two of the eight root test files
 * were named explicitly — each with a comment saying, in as many words, that
 * the directory "is not covered by any glob in this workflow".
 *
 * What was orphaned: 1383 assertions, including the Rúnar-vs-Plonky3 field
 * arithmetic vectors (BabyBear, BabyBear-ext4, Merkle, FRI colinearity) that
 * are the provenance for the Go-only STARK codegen, plus the version-consistency
 * and script-size gates. They all pass — which is the point. Nothing would have
 * told anyone if they stopped.
 *
 * Naming a third file would have repeated the mistake. This test requires the
 * DIRECTORY to be covered, so a vector file added tomorrow is gated the day it
 * lands.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

const rootTests = readdirSync(join(REPO, 'tests'))
  .filter((f) => f.endsWith('.test.ts'))
  .sort();

/** Every `npx vitest run <args...>` invocation in the CI workflow. */
function ciVitestArgs(): string[][] {
  const yml = read('.github/workflows/ci.yml');
  const out: string[][] = [];
  for (const line of yml.split('\n')) {
    const m = line.match(/npx vitest run\s+(.*)$/);
    if (m) out.push(m[1]!.trim().split(/\s+/).filter((a) => !a.startsWith('-')));
  }
  return out;
}

/** True when some CI invocation covers the whole root `tests/` directory. */
function ciCoversRootDir(): boolean {
  return ciVitestArgs().some((args) =>
    args.some((a) => a === 'tests' || a === 'tests/' || a === './tests' || a === './tests/'),
  );
}

/** Root test files a CI invocation names explicitly. */
function ciNamedRootTests(): Set<string> {
  const named = new Set<string>();
  for (const args of ciVitestArgs()) {
    for (const a of args) {
      const m = a.match(/^\.?\/?tests\/([^/]+\.test\.ts)$/);
      if (m) named.add(m[1]!);
    }
  }
  return named;
}

/** Expand a package.json script chain, following `pnpm run <name>` references. */
function expandScript(name: string, scripts: Record<string, string>, seen = new Set<string>()): string {
  if (seen.has(name)) return '';
  seen.add(name);
  const body = scripts[name];
  if (body === undefined) return '';
  let out = body;
  for (const m of body.matchAll(/pnpm run ([A-Za-z0-9:_-]+)/g)) {
    out += ' ' + expandScript(m[1]!, scripts, seen);
  }
  return out;
}

describe('R-110: CI executes the repo-root tests/ directory', () => {
  it('the directory is non-empty (a silent sweep would pass vacuously)', () => {
    expect(rootTests.length).toBeGreaterThanOrEqual(5);
  });

  it('every root test file is executed by CI', () => {
    if (ciCoversRootDir()) return; // the directory form covers all of them
    const named = ciNamedRootTests();
    const uncovered = rootTests.filter((f) => !named.has(f));
    expect(
      uncovered,
      `.github/workflows/ci.yml never runs these root tests: ${uncovered.join(', ')}. ` +
        `Every 'npx vitest run' in that workflow is path-scoped and root tests/ is not ` +
        `a workspace member, so turbo does not reach it either. Run the DIRECTORY ` +
        `(npx vitest run tests/) rather than naming another file.`,
    ).toEqual([]);
  });

  it('the test:ci script chain reaches the root tests/ directory', () => {
    const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
    const chain = expandScript('test:ci', pkg.scripts);
    expect(chain.length, 'test:ci not found in package.json').toBeGreaterThan(0);
    expect(
      /vitest run (\.\/)?tests\/?(\s|$)/.test(chain),
      `test:ci expands to a chain that never runs the repo-root tests/ directory. ` +
        `A developer running the documented pre-push command would not execute ` +
        `${rootTests.length} test files, including the Plonky3 vector gates.`,
    ).toBe(true);
  });
});
