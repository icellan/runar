import { describe, expect, it, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROOT = resolve(__dirname, '..');
const RELEASE_SH = resolve(ROOT, 'scripts/release.sh');

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
