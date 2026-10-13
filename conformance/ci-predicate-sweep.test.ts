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
 * (`conformance/anf-interpreter/driver-gate.ts`'s `isCiEnv`: CI is "set to
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

// The predicate's own definition and its direct unit test legitimately spell
// out `env.CI` / `process.env.CI` — that's the implementation being reused,
// not a site that should call it. This file also mentions the pattern only
// inside comments/regexes above, never as a live check, so it is not its own
// violation, but is excluded anyway for clarity.
const EXCLUDED = new Set([
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
