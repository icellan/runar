/**
 * N-236: ~30 conformance tests detected CI with `process.env.CI === 'true'`.
 * A CI runner that exports `CI=1` (a common convention — GitLab CI, many
 * self-hosted runners) is NOT `'true'`, so every one of these checks silently
 * fell through to the "local, permissive" branch: missing-tier assertions
 * were skipped, and `decideMissingTierAction` / `decideMissingCompilerAction`
 * (conformance/analyzer/run.ts, conformance/runner/runner.ts) returned
 * `'warn'` instead of `'fail'` for a dropped tier under `CI=1`. One fixture
 * (`int-literal-parity.test.ts`) used a bare `process.env.CI` truthy check
 * instead, which has the opposite problem: `CI='0'` / `CI='false'` are
 * non-empty strings and so are truthy in JS, wrongly counting as CI.
 *
 * N-166 already solved this once, for the ANF driver gate only
 * (`isCiEnv`, now defined in `conformance/env.ts` — see N-250 below — and at
 * the time in `conformance/anf-interpreter/driver-gate.ts`: CI is "set to
 * anything but '', '0' or 'false' (case-insensitive)", or
 * `GITHUB_ACTIONS=true`). This sweeps every other conformance CI check onto
 * that same predicate instead of leaving `~30` private reimplementations to
 * drift from it and from each other.
 *
 * Proves: no file under conformance/ (other than the predicate's own
 * definition and its unit test) spells out a raw `process.env.CI` /
 * `env.CI === 'true'` check — every site routes through `isCiEnv`. Does not
 * prove the gated assertions are individually correct, nor that CI actually
 * sets `CI=1` anywhere today — only that a runner which does would no longer
 * be silently ignored.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const CONFORMANCE_DIR = dirname(fileURLToPath(import.meta.url));

// The predicate's own definition (conformance/env.ts, since N-250 — see
// below) and its direct unit test legitimately spell out `env.CI` /
// `process.env.CI` — that's the implementation being reused, not a site that
// should call it. driver-gate.ts/.test.ts are also excluded: driver-gate.ts
// keeps a backward-compatible re-export of isCiEnv (N-250) and its test
// exercises that re-export. This file also mentions the pattern only inside
// comments/regexes above, never as a live check, so it is not its own
// violation, but is excluded anyway for clarity.
const EXCLUDED = new Set([
  join(CONFORMANCE_DIR, 'env.ts'),
  join(CONFORMANCE_DIR, 'anf-interpreter', 'driver-gate.ts'),
  join(CONFORMANCE_DIR, 'anf-interpreter', 'driver-gate.test.ts'),
  join(CONFORMANCE_DIR, 'ci-predicate-sweep.test.ts'),
]);

const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', '.git', 'coverage']);

function listTsFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      listTsFiles(full, out);
    } else if (entry.endsWith('.ts') && !entry.includes('.runar.')) {
      out.push(full);
    }
  }
  return out;
}

// `X.CI === 'true'` (X is `process.env` or a local `env` parameter) and any
// raw `process.env.CI` access (including a bare truthy check, as
// int-literal-parity used) are both the anti-pattern: the fix in every case
// is to call `isCiEnv(...)` instead of reading `.CI` directly.
const BAD_EQUALS_TRUE = /\.CI\s*===\s*['"]true['"]/;
const BAD_RAW_PROCESS_ENV_CI = /\bprocess\.env\.CI\b/;

describe('N-236: conformance CI checks route through the shared isCiEnv predicate', () => {
  const files = listTsFiles(CONFORMANCE_DIR).filter((f) => !EXCLUDED.has(f));

  it('scans a non-trivial number of conformance source files', () => {
    expect(files.length).toBeGreaterThan(100);
  });

  it('no file reimplements the CI check instead of calling isCiEnv', () => {
    const violations: string[] = [];
    for (const file of files) {
      const src = readFileSync(file, 'utf8');
      const lines = src.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (BAD_EQUALS_TRUE.test(line) || BAD_RAW_PROCESS_ENV_CI.test(line)) {
          violations.push(`${relative(CONFORMANCE_DIR, file)}:${i + 1}: ${line.trim()}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });
});

/**
 * N-250: isCiEnv used to be DEFINED in conformance/anf-interpreter/driver-gate.ts
 * — a file that is otherwise about the ANF cross-interpreter driver gate
 * (enforceDriverGate, GateDriver) — yet after N-236's sweep it was imported
 * by ~44 unrelated conformance suites plus analyzer/run.ts and
 * runner/runner.ts, none of which care about ANF drivers at all. That made
 * driver-gate.ts a load-bearing dependency for most of conformance/ despite
 * its name and doc comment describing a narrow, unrelated concern.
 *
 * Fix: isCiEnv is defined in the neutral conformance/env.ts, and
 * driver-gate.ts re-exports it only for its own backward compatibility
 * (its direct unit test, driver-gate.test.ts, still imports the re-export to
 * prove that compatibility shim works). Every other caller imports isCiEnv
 * from env.ts directly.
 *
 * Proves: conformance/env.ts exists and defines isCiEnv, and no file outside
 * driver-gate.ts / driver-gate.test.ts imports isCiEnv from driver-gate.js.
 * Does not prove isCiEnv's runtime behavior (driver-gate.test.ts and the
 * N-236 sweep above cover that) — only where the symbol is defined and how
 * it is reached.
 */
describe('N-250: isCiEnv is defined in the neutral conformance/env.ts', () => {
  const allFiles = listTsFiles(CONFORMANCE_DIR);
  // driver-gate.ts keeps a compatibility re-export; driver-gate.test.ts
  // legitimately imports through that re-export to prove the shim works.
  const ALLOWED_DRIVER_GATE_IMPORTERS = new Set([
    join(CONFORMANCE_DIR, 'anf-interpreter', 'driver-gate.ts'),
    join(CONFORMANCE_DIR, 'anf-interpreter', 'driver-gate.test.ts'),
  ]);
  const IMPORTS_IS_CI_ENV_FROM_DRIVER_GATE =
    /import\s*\{[^}]*\bisCiEnv\b[^}]*\}\s*from\s*['"][^'"]*driver-gate(?:\.js)?['"]/;

  it('conformance/env.ts exports isCiEnv', () => {
    const envTs = join(CONFORMANCE_DIR, 'env.ts');
    const src = readFileSync(envTs, 'utf8');
    expect(src).toMatch(/export function isCiEnv\(/);
  });

  it('no file outside driver-gate.ts/driver-gate.test.ts imports isCiEnv from driver-gate.js', () => {
    const violations: string[] = [];
    for (const file of allFiles) {
      if (ALLOWED_DRIVER_GATE_IMPORTERS.has(file)) continue;
      const src = readFileSync(file, 'utf8');
      if (IMPORTS_IS_CI_ENV_FROM_DRIVER_GATE.test(src)) {
        violations.push(relative(CONFORMANCE_DIR, file));
      }
    }
    expect(violations).toEqual([]);
  });
});
