import { describe, expect, it, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(__dirname, '..');
const RELEASE_SH = resolve(ROOT, 'scripts/release.sh');
const PUBLISH_SH = resolve(ROOT, 'scripts/publish-all.sh');

// A version that exists in no tag namespace, so even a catastrophically broken
// dry run cannot collide with a real release tag.
const VERSION = '99.99.99-dryrun';

/**
 * `scripts/release.sh` is the one script in this repo that commits, tags,
 * pushes and publishes. Two recorded defects:
 *
 *   R-045 / CL-BUG-074 — it re-ran `git add -A && git commit` and
 *   `git tag "v$NEW"` that `scripts/bump-version.sh` had *already* performed
 *   two steps earlier. Under `set -euo pipefail` the duplicate commit exits 1
 *   ("nothing to commit, working tree clean") and the duplicate tag exits 128
 *   ("tag already exists"), so the release aborted *after* the bump had been
 *   committed and tagged locally and *before* anything was pushed or
 *   published — a half-finished release.
 *
 *   CL-BUG-085 — it invoked no test suite, no lint and no typecheck anywhere
 *   before commit, tag, push and publish. `grep -E 'test|vitest|pytest|cargo
 *   test|go test|rake|gradlew|conformance|lint|typecheck' scripts/release.sh`
 *   matched nothing in all 56 lines.
 *
 *   R-049 — the gate `pnpm run test:all` alone still let two vacuous passes
 *   through. A tier whose toolchain is absent is unmeasured, not green; and
 *   the conformance runner exits 0 on a filtered run that proved nothing. So
 *   the gate now (a) aborts on a missing toolchain and (b) asserts the
 *   runner's reported COUNTS against the fixtures on disk. `--check` runs
 *   every gate and releases nothing, which is the mode a human can actually
 *   exercise; the tests below drive its assertion helper directly.
 *
 * These tests drive the script's `--dry-run` mode, which prints the command
 * plan prefixed `[dry-run] ` and executes none of it. They assert the *ordered
 * sequence of commands the script would run* — an exit-0 dry run that silently
 * skipped a step would pass a bare exit-code check and prove nothing.
 *
 * Nothing here may commit, tag, push or publish. The final test pins that.
 */

function plan(...args: string[]): { stdout: string; steps: string[]; status: number } {
  let stdout = '';
  let status = 0;
  try {
    stdout = execFileSync('bash', [RELEASE_SH, ...args], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env },
    });
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    status = e.status ?? 1;
    stdout = (e.stdout ?? '') + (e.stderr ?? '');
  }
  const steps = stdout
    .split('\n')
    .filter((l) => l.startsWith('[dry-run] '))
    .map((l) => l.slice('[dry-run] '.length).trim());
  return { stdout, steps, status };
}

const indexOfStep = (steps: string[], needle: string | RegExp): number =>
  steps.findIndex((s) => (typeof needle === 'string' ? s.includes(needle) : needle.test(s)));

describe('scripts/release.sh — dry-run command plan', () => {
  let steps: string[];
  let stdout: string;

  beforeAll(() => {
    const r = plan('--dry-run', VERSION);
    expect(r.status, `dry run exited ${r.status}:\n${r.stdout}`).toBe(0);
    steps = r.steps;
    stdout = r.stdout;
  });

  it('emits a non-empty plan (an exit-0 no-op is not a passing release)', () => {
    expect(steps.length, `no [dry-run] plan lines in:\n${stdout}`).toBeGreaterThanOrEqual(6);
  });

  it('runs a test gate, and runs it before anything is mutated', () => {
    const test = indexOfStep(steps, /pnpm run (test|test:all|test:ci)\b/);
    expect(test, `no test-suite step in plan:\n${steps.join('\n')}`).toBeGreaterThanOrEqual(0);

    const bump = indexOfStep(steps, 'scripts/bump-version.sh');
    expect(bump).toBeGreaterThanOrEqual(0);
    // The whole point of R-045 is "don't fail after you have already mutated".
    expect(test, 'the test gate must run before bump-version.sh commits and tags').toBeLessThan(bump);
  });

  it('also gates on lint and typecheck before mutating', () => {
    const bump = indexOfStep(steps, 'scripts/bump-version.sh');
    for (const gate of ['lint:silent-skips', 'typecheck']) {
      const i = indexOfStep(steps, gate);
      expect(i, `no ${gate} step in plan:\n${steps.join('\n')}`).toBeGreaterThanOrEqual(0);
      expect(i).toBeLessThan(bump);
    }
  });

  it('delegates the commit and the v-tag to bump-version.sh instead of repeating them', () => {
    const bump = steps.filter((s) => s.includes('scripts/bump-version.sh'));
    expect(bump, 'expected exactly one bump-version.sh invocation').toHaveLength(1);
    expect(bump[0]).toContain(VERSION);

    // R-045: these are the two duplicated commands that aborted the release.
    expect(
      steps.filter((s) => /^git commit\b/.test(s)),
      `release.sh must not re-commit; bump-version.sh already did:\n${steps.join('\n')}`,
    ).toHaveLength(0);
    expect(
      steps.filter((s) => /^git add\b/.test(s)),
      'release.sh must not re-stage; bump-version.sh already did',
    ).toHaveLength(0);
    expect(
      steps.filter((s) => s === `git tag v${VERSION}`),
      `release.sh must not re-create v${VERSION}; bump-version.sh already tagged it`,
    ).toHaveLength(0);
  });

  it('still creates the two Go-module tags, which bump-version.sh does not', () => {
    expect(steps).toContain(`git tag compilers/go/v${VERSION}`);
    expect(steps).toContain(`git tag packages/runar-go/v${VERSION}`);
  });

  it('pushes the branch and all three tags, then publishes, in that order', () => {
    const pushBranch = indexOfStep(steps, /^git push$/);
    const pushTags = indexOfStep(steps, /^git push origin /);
    const publish = indexOfStep(steps, 'scripts/publish-all.sh');

    expect(pushBranch, 'no `git push` in plan').toBeGreaterThanOrEqual(0);
    expect(pushTags, 'no tag push in plan').toBeGreaterThanOrEqual(0);
    expect(publish, 'no publish-all.sh in plan').toBeGreaterThanOrEqual(0);

    expect(steps[pushTags]).toContain(`v${VERSION}`);
    expect(steps[pushTags]).toContain(`compilers/go/v${VERSION}`);
    expect(steps[pushTags]).toContain(`packages/runar-go/v${VERSION}`);

    const bump = indexOfStep(steps, 'scripts/bump-version.sh');
    expect(bump).toBeLessThan(pushBranch);
    expect(pushBranch).toBeLessThan(pushTags);
    expect(pushTags).toBeLessThan(publish);
    expect(publish, 'publish must be the last step').toBe(steps.length - 1);
  });
});

describe('scripts/release.sh — flags', () => {
  it('--skip-tests drops only the test gate, keeps the rest of the plan, and warns', () => {
    const withTests = plan('--dry-run', VERSION);
    const skipped = plan('--dry-run', '--skip-tests', VERSION);
    expect(skipped.status).toBe(0);

    expect(indexOfStep(skipped.steps, /pnpm run test/)).toBe(-1);
    expect(skipped.steps.length).toBeLessThan(withTests.steps.length);

    // Everything that is not a test step survives.
    for (const needle of [
      'scripts/bump-version.sh',
      `git tag compilers/go/v${VERSION}`,
      'git push',
      'scripts/publish-all.sh',
    ]) {
      expect(indexOfStep(skipped.steps, needle), `--skip-tests dropped ${needle}`).toBeGreaterThanOrEqual(0);
    }
    expect(skipped.stdout.toUpperCase()).toContain('WARNING');
  });

  it('rejects an unknown flag and a missing version instead of guessing', () => {
    expect(plan('--dry-run', '--nope', VERSION).status).not.toBe(0);
    expect(plan('--dry-run').status).not.toBe(0);
  });
});

describe('scripts/release.sh — the dry run must not touch git state', () => {
  it('creates no commit and no tag in this checkout', () => {
    const head = () => execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
    const before = head();
    plan('--dry-run', VERSION);
    expect(head()).toBe(before);
    const tags = execFileSync('git', ['tag', '--list', `*${VERSION}*`], { cwd: ROOT, encoding: 'utf8' }).trim();
    expect(tags, `dry run created tags: ${tags}`).toBe('');
  });

  it('routes every side-effecting command through the dry-run guard', () => {
    const src = readFileSync(RELEASE_SH, 'utf8');
    const offenders = src
      .split('\n')
      .map((line, i) => [i + 1, line] as const)
      .filter(([, line]) => !line.trimStart().startsWith('#'))
      // A bare `git push` / `git tag` / `git commit` / `pnpm -r publish` at the
      // start of a statement bypasses the guard and would fire for real.
      .filter(([, line]) => /(^|;|&&|\|\|)\s*(git\s+(push|tag|commit|add)|pnpm\s+-r\s+publish|cargo\s+publish|npm\s+publish)\b/.test(line));
    expect(
      offenders.map(([n, l]) => `${n}: ${l.trim()}`),
      'unguarded side-effecting command in release.sh',
    ).toEqual([]);
  });
});


/**
 * Drive one of release.sh's gate helpers directly. Sourcing the script with
 * RUNAR_RELEASE_LIB=1 defines the helpers and runs nothing else, so the gate
 * logic is testable without a release — and, more to the point, testable
 * against the *vacuous* runner output that an exit-code check waves through.
 */
function lib(fn: string, ...args: string[]): { status: number; out: string } {
  try {
    const out = execFileSync(
      'bash',
      ['-c', 'RUNAR_RELEASE_LIB=1 . "$1"; shift; "$@"', 'bash', RELEASE_SH, fn, ...args],
      { cwd: ROOT, encoding: 'utf8', env: { ...process.env, RUNAR_RELEASE_ROOT: ROOT } },
    );
    return { status: 0, out };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? 1, out: (e.stdout ?? '') + (e.stderr ?? '') };
  }
}

describe('scripts/release.sh — the gates R-049 added', () => {
  let steps: string[];

  beforeAll(() => {
    const r = plan('--dry-run', VERSION);
    expect(r.status, r.stdout).toBe(0);
    steps = r.steps;
  });

  it('gates on toolchains, the 7-tier golden board and the script-size baseline, all before mutating', () => {
    const bump = indexOfStep(steps, 'scripts/bump-version.sh');
    expect(bump).toBeGreaterThanOrEqual(0);

    const gates: Array<[string, RegExp]> = [
      ['toolchain check', /command -v .*\bzig\b.*\bruby\b/],
      ['7-tier golden conformance', /conformance && .*npx tsx runner\/index\.ts/],
      ['script-size baseline', /script-size-check/],
    ];
    for (const [name, re] of gates) {
      const i = indexOfStep(steps, re);
      expect(i, `no ${name} gate in plan:\n${steps.join('\n')}`).toBeGreaterThanOrEqual(0);
      expect(i, `the ${name} gate must run before bump-version.sh`).toBeLessThan(bump);
    }
  });

  it('pins the conformance concurrency (the default limiter has OOM-killed release boxes)', () => {
    const i = indexOfStep(steps, /npx tsx runner\/index\.ts/);
    expect(steps[i]).toMatch(/RUNAR_CONFORMANCE_CONCURRENCY=\d+/);
  });

  it('aborts when a tier toolchain is missing rather than releasing on a partial board', () => {
    // command -v is a builtin, so an empty PATH still resolves nothing.
    let status = 0;
    let out = '';
    try {
      out = execFileSync(
        'bash',
        ['-c', 'RUNAR_RELEASE_LIB=1 . "$1"; PATH=/nonexistent-dir gate_toolchains', 'bash', RELEASE_SH],
        { cwd: ROOT, encoding: 'utf8', env: { ...process.env, RUNAR_RELEASE_ROOT: ROOT } },
      );
    } catch (err) {
      const e = err as { status?: number; stdout?: string; stderr?: string };
      status = e.status ?? 1;
      out = (e.stdout ?? '') + (e.stderr ?? '');
    }
    expect(status, `gate_toolchains passed with an empty PATH:\n${out}`).not.toBe(0);
    expect(out).toMatch(/missing toolchains/);
  });
});

describe('scripts/release.sh — the conformance gate refuses a vacuous pass', () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'runar-release-gate-'));
  });

  // The runner colours its summary line, so the green fixture below carries
  // real escape codes: the gate has to strip ANSI before it can match.
  const ESC = String.fromCharCode(27);
  const BOLD = `${ESC}[1m`;
  const RESET = `${ESC}[0m`;
  const GREEN = `${ESC}[32m`;

  const logWith = (name: string, body: string): string => {
    const p = join(dir, name);
    writeFileSync(p, body, 'utf8');
    return p;
  };

  it('accepts a full green board, colour codes and all', () => {
    const log = logWith(
      'green.log',
      `  PASS p2pkh\n${BOLD}Summary:${RESET} ${GREEN}74 passed${RESET}, 0 failed, 0 skipped (74 total)\n`,
    );
    const r = lib('assert_conformance_summary', log, '74');
    expect(r.status, r.out).toBe(0);
    expect(r.out).toMatch(/74\/74 fixtures passed/);
  });

  it('rejects a filtered run that exercised fewer fixtures than exist on disk', () => {
    const log = logWith('short.log', 'Summary: 3 passed, 0 failed, 71 skipped (74 total)\n');
    const r = lib('assert_conformance_summary', log, '74');
    expect(r.status).not.toBe(0);
    expect(r.out).toMatch(/only 3 of 74/);
  });

  it('rejects the 0-passed/0-failed board that every exit-code check calls green', () => {
    const log = logWith('vacuous.log', 'Summary: 0 passed, 0 failed, 0 skipped (0 total)\n');
    const r = lib('assert_conformance_summary', log, '74');
    expect(r.status, `a 0/0 board was accepted:\n${r.out}`).not.toBe(0);
  });

  it('rejects a board with failures', () => {
    const log = logWith('red.log', 'Summary: 73 passed, 1 failed, 0 skipped (74 total)\n');
    const r = lib('assert_conformance_summary', log, '74');
    expect(r.status).not.toBe(0);
    expect(r.out).toMatch(/1 conformance fixture/);
  });

  it('treats a missing summary line as failure, not as silence', () => {
    const log = logWith('crashed.log', 'Error: Cannot find module tsx\n');
    const r = lib('assert_conformance_summary', log, '74');
    expect(r.status).not.toBe(0);
    expect(r.out).toMatch(/no Summary line/);
  });

  it('counts the fixtures on disk rather than trusting a hardcoded number', () => {
    const r = lib('conformance_fixture_count');
    expect(r.status, r.out).toBe(0);
    expect(Number(r.out.trim())).toBeGreaterThan(50);
  });
});

describe('scripts/release.sh — --check', () => {
  it('is rejected alongside --dry-run: one prints the plan, the other runs the gates', () => {
    const r = plan('--dry-run', '--check', VERSION);
    expect(r.status).not.toBe(0);
    expect(r.stdout).toMatch(/mutually exclusive/);
  });

  it('routes every irreversible command through the mutate guard', () => {
    // Same shape as the R-045 guard test, restated for --check: the mode that
    // runs the gates for real must not be able to reach a git or publish
    // command.
    const src = readFileSync(RELEASE_SH, 'utf8');
    const mutating = src.split('\n').filter((l) => /^\s*mutate\s/.test(l));
    expect(
      mutating.length,
      'no mutate-guarded commands found — did the guard get renamed?',
    ).toBeGreaterThanOrEqual(6);
    expect(src).toMatch(/if \[ -n "\$DRY_RUN" \] \|\| \[ -n "\$CHECK" \]/);
  });
});

/**
 * `scripts/publish-all.sh` is the registry side of the release. Recorded
 * defects (R-049):
 *
 *   * `return 1` in the twine failure path — a `return` in a script body, not
 *     a function, so bash answered "return: can only `return` from a function
 *     or sourced script" and the operator never saw the upload error.
 *   * no publish path for the Ruby gem, even though README.md documents
 *     `gem install runar-lang` and bump-version.sh bumps the gemspec on every
 *     release. Java and Zig have no upload channel at all, which is now
 *     stated in the output instead of being silently absent.
 *
 * --dry-run is a pure plan printer, so these tests are offline: nothing here
 * contacts npm, crates.io, PyPI or RubyGems.
 */
describe('scripts/publish-all.sh — dry-run plan', () => {
  let out: string;

  beforeAll(() => {
    out = execFileSync('bash', [PUBLISH_SH, '--dry-run'], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env },
    });
  });

  it('plans an upload for every tier that has a registry', () => {
    const tiers: Array<[string, RegExp]> = [
      ['npm', /\[dry-run\].*pnpm -r publish --access public/],
      ['crates.io', /\[dry-run\].*cargo publish/],
      ['PyPI', /\[dry-run\].*twine upload dist/],
      ['RubyGems', /\[dry-run\].*gem build runar\.gemspec.*gem push/],
    ];
    for (const [tier, re] of tiers) {
      expect(out, `no ${tier} publish step in the plan:\n${out}`).toMatch(re);
    }
  });

  it('publishes the three Rust crates in dependency order', () => {
    const crates = ['compilers/rust', 'packages/runar-rs-macros', 'packages/runar-rs'];
    const at = crates.map((c) => out.indexOf(`${c} && cargo publish`));
    expect(
      at.every((i) => i >= 0),
      `not all crates in the plan:\n${out}`,
    ).toBe(true);
    expect(at[0]).toBeLessThan(at[1]);
    expect(at[1]).toBeLessThan(at[2]);
  });

  it('names the tiers it does NOT upload instead of omitting them', () => {
    expect(out).toMatch(/Go modules \(git tags\)/);
    expect(out).toMatch(/Zig package \(git tags\)/);
    expect(out, 'the Java gap must be visible at release time').toMatch(/Java packages — NOT PUBLISHED/);
  });

  it('does not claim anything was published', () => {
    expect(out).not.toMatch(/npm packages published$/m);
    expect(out).toMatch(/not performed/);
  });

  it('rejects an unrecognised argument rather than treating it as a real publish', () => {
    let status = 0;
    try {
      execFileSync('bash', [PUBLISH_SH, '--nope'], { cwd: ROOT, encoding: 'utf8', stdio: 'pipe' });
    } catch (err) {
      status = (err as { status?: number }).status ?? 1;
    }
    expect(status).not.toBe(0);
  });

  it('has no `return` outside a function (the bash diagnostic that masked the twine error)', () => {
    const lines = readFileSync(PUBLISH_SH, 'utf8').split('\n');
    let depth = 0;
    const offenders: string[] = [];
    lines.forEach((line, i) => {
      if (/^[A-Za-z_][A-Za-z0-9_]*\(\)\s*\{/.test(line)) depth += 1;
      else if (depth > 0 && /^\}/.test(line)) depth -= 1;
      else if (depth === 0 && /^\s*return\b/.test(line)) offenders.push(`${i + 1}: ${line.trim()}`);
    });
    expect(
      offenders,
      'a `return` in the script body exits with a shell diagnostic, not your error',
    ).toEqual([]);
  });
});


/**
 * R-049, found while running `--check` for real: the release gate was
 * `pnpm --filter runar-conformance run script-size-check`, and conformance/ is
 * not a pnpm workspace member (pnpm-workspace.yaml lists packages/* and
 * integration/ts). pnpm printed "No projects matched the filters" and exited
 * 0, so the gate — and the CI job of the same name — ran nothing at all.
 */
describe('scripts/release.sh — the script-size gate runs something', () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'runar-release-size-'));
  });

  const logWith = (name: string, body: string): string => {
    const p = join(dir, name);
    writeFileSync(p, body, 'utf8');
    return p;
  };

  it('does not invoke the checker through a pnpm filter that matches no project', () => {
    const src = readFileSync(RELEASE_SH, 'utf8');
    const live = src
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('#'))
      .join('\n');
    expect(live, 'pnpm --filter runar-conformance exits 0 having run nothing').not.toMatch(
      /--filter runar-conformance/,
    );
    expect(live).toMatch(/runner\/script-size-check\.ts/);
  });

  it('accepts a full board', () => {
    const log = logWith('ok.log', 'Summary: ok=74 warn=0 fail=0 missing=0 (total=74)\n');
    const r = lib('assert_script_size_summary', log, '74');
    expect(r.status, r.out).toBe(0);
    expect(r.out).toMatch(/74\/74 fixtures within the size baseline/);
  });

  it('rejects a regression and a fixture with no baseline', () => {
    const failed = lib(
      'assert_script_size_summary',
      logWith('fail.log', 'Summary: ok=73 warn=0 fail=1 missing=0 (total=74)\n'),
      '74',
    );
    expect(failed.status).not.toBe(0);

    const missing = lib(
      'assert_script_size_summary',
      logWith('missing.log', 'Summary: ok=73 warn=0 fail=0 missing=1 (total=74)\n'),
      '74',
    );
    expect(missing.status, 'an unbaselined fixture is unmeasured, not passing').not.toBe(0);
  });

  it('rejects a run that covered fewer fixtures than exist, and one with no summary at all', () => {
    const short = lib(
      'assert_script_size_summary',
      logWith('short.log', 'Summary: ok=2 warn=0 fail=0 missing=0 (total=2)\n'),
      '74',
    );
    expect(short.status).not.toBe(0);
    expect(short.out).toMatch(/covered 2 of 74/);

    const silent = lib(
      'assert_script_size_summary',
      logWith('silent.log', 'No projects matched the filters\n'),
      '74',
    );
    expect(silent.status, 'the exact output the broken gate produced must not pass').not.toBe(0);
    expect(silent.out).toMatch(/no Summary line/);
  });
});
