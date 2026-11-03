/**
 * F-174 (CL-BUG-239 / CL-GAP-133) — `scripts/lean-verify.sh` had drifted from
 * the `runar-verification` job it declares it must mirror, and `pnpm run
 * test:ci` never noticed because the lean leg was never made strict.
 *
 * Two independent defects, both confirmed at HEAD before the fix:
 *
 *   1. `package.json`'s `test:ci` sets `RUNAR_INTEGRATION_STRICT=1` for the
 *      integration leg (`RUNAR_INTEGRATION_STRICT=1 pnpm run integration:all`)
 *      so a missing toolchain hard-fails CI, but never sets
 *      `RUNAR_LEAN_STRICT` for the sibling `pnpm run lean:verify` leg.
 *      `scripts/lean-verify.sh` defaults `RUNAR_LEAN_STRICT` to `0`, under
 *      which a missing `lake` prints a notice and exits 0 — so on any machine
 *      without `lake` on PATH (every normal CI runner image, since `lake`
 *      comes from installing elan, which `test:ci` never does),
 *      `pnpm run test:ci` reports green while the entire Lean 4 verification
 *      gate silently never ran.
 *
 *   2. Even when `lake` IS present, the script's own header says "steps added
 *      in CI must be reflected here so `pnpm test:ci` does not drift" — but
 *      `.github/workflows/ci.yml`'s `runar-verification` job builds and runs
 *      the `pipelineConformance` binary (via
 *      `runar-verification/scripts/run-pipeline-conformance.sh`) and asserts
 *      the README discovered-fixture-count matches `goldenLoad`'s runtime
 *      count; `scripts/lean-verify.sh` did neither, so even a strict local
 *      run skipped two of CI's gates.
 *
 * What this proves: the `test:ci` script string now wires `RUNAR_LEAN_STRICT=1`
 * the same way it already wires `RUNAR_INTEGRATION_STRICT=1`, and every
 * `lake env <binary>` / `scripts/<name>.sh` invocation and `lake build`
 * target that CI's `runar-verification` job performs has a matching line in
 * `scripts/lean-verify.sh` (by name, not by exact text, so comment rewording
 * doesn't false-fail this). The last test exercises the script for real (no
 * `lake` on PATH) and shows `RUNAR_LEAN_STRICT=1` now actually turns the
 * no-op skip into a hard failure — the mechanism `test:ci` depends on.
 *
 * What this does not prove: it never runs Lean, builds anything under
 * `runar-verification/`, or executes `pipelineConformance` /
 * `run-pipeline-conformance.sh` / the README check for real — those steps
 * are confirmed PRESENT in the script, not confirmed to pass when a machine
 * with `lake` actually runs them. Whether the Lean gates themselves are
 * correct is outside this test's scope.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

/** Drop full-line comments so a name mentioned only in prose doesn't count. */
const codeLines = (text: string) => text.split('\n').filter((l) => !/^\s*#/.test(l));

/** The lines of an indented block that starts at `header` (exact line match). */
function block(lines: string[], header: RegExp): string[] | undefined {
  const start = lines.findIndex((l) => header.test(l));
  if (start < 0) return undefined;
  const indent = lines[start]!.match(/^ */)![0].length;
  const out: string[] = [];
  for (const l of lines.slice(start + 1)) {
    if (l.trim() === '') continue;
    if (l.match(/^ */)![0].length <= indent) break;
    out.push(l);
  }
  return out;
}

function runarVerificationJob(): string[] {
  const lines = codeLines(read('.github/workflows/ci.yml'));
  const body = block(lines, /^ {2}runar-verification:\s*$/);
  expect(body, 'ci.yml: runar-verification job not found').toBeDefined();
  return body!;
}

describe('F-174: scripts/lean-verify.sh stays wired to and in sync with ci.yml', () => {
  it('package.json test:ci sets RUNAR_LEAN_STRICT=1, mirroring RUNAR_INTEGRATION_STRICT=1', () => {
    const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
    const testCi = pkg.scripts['test:ci'];
    expect(testCi, 'package.json: scripts.test:ci not found').toBeDefined();
    // The existing, already-correct pattern for the sibling integration leg.
    expect(testCi).toMatch(/RUNAR_INTEGRATION_STRICT=1 pnpm run integration:all/);
    // The defect: the lean leg never got the same treatment.
    expect(testCi).toMatch(/RUNAR_LEAN_STRICT=1 pnpm run lean:verify/);
  });

  const job = runarVerificationJob();
  const jobText = job.join('\n');
  const scriptText = read('scripts/lean-verify.sh');

  // Every Lean binary ci.yml runs via `lake env ./.lake/build/bin/<name>`.
  const binaryNames = [...jobText.matchAll(/lake env \.\/\.lake\/build\/bin\/(\w+)/g)].map((m) => m[1]!);
  // Every helper script ci.yml invokes under `scripts/<name>.sh`.
  const scriptNames = [...jobText.matchAll(/scripts\/([\w-]+\.sh)/g)].map((m) => m[1]!);
  // The one-line `lake build <targets...>` that names every ad-hoc exe target.
  const buildTargetsLine = job.find((l) => /^\s*lake build pipelineGolden\b/.test(l));
  expect(buildTargetsLine, "ci.yml: 'lake build pipelineGolden ...' target line not found").toBeDefined();
  const buildTargets = buildTargetsLine!.trim().split(/\s+/).slice(2);

  const names = [...new Set([...binaryNames, ...scriptNames, ...buildTargets])];
  expect(names.length, 'ci.yml: no binaries/scripts/build-targets extracted from runar-verification job').toBeGreaterThan(0);

  for (const name of names) {
    it(`scripts/lean-verify.sh references ${name}, same as ci.yml's runar-verification job`, () => {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      expect(scriptText).toMatch(new RegExp(`\\b${escaped}\\b`));
    });
  }

  it('scripts/lean-verify.sh: RUNAR_LEAN_STRICT=1 hard-fails when lake is absent; default skips', () => {
    // A PATH with no `lake` on it, deterministically, regardless of what is
    // installed on the machine running this test. The script's early-exit
    // branch only uses bash builtins (`command -v`, `cd`, `echo`, `exit`), so
    // no other binary needs to be reachable for this path to be exercised.
    const run = (env: Record<string, string>) =>
      // Absolute path to bash so spawnSync can find the interpreter itself
      // without consulting the (deliberately bogus) child PATH below; the
      // script's own `command -v lake` lookup still uses that PATH.
      spawnSync('/bin/bash', ['scripts/lean-verify.sh'], {
        cwd: REPO,
        encoding: 'utf-8',
        env: { PATH: '/f174-lean-verify-test-no-such-dir', ...env },
      });

    const strict = run({ RUNAR_LEAN_STRICT: '1' });
    expect(strict.status, `stderr: ${strict.stderr}`).toBe(1);
    expect(strict.stderr).toMatch(/lake/i);

    const lax = run({});
    expect(lax.status, `stderr: ${lax.stderr}`).toBe(0);
    expect(lax.stderr).toMatch(/skipping/i);
  });
});
