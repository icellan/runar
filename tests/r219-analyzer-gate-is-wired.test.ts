/**
 * R-219 (CL-GAP-065): the Bitcoin Script static analyzer is REAL and
 * implemented in all seven tiers, but it has ZERO CI wiring —
 * `conformance/analyzer/run.ts` can only be run by hand, and the analyzer
 * README still describes the driver as "planned" although it exists. A working
 * seven-tier gate that nothing runs.
 *
 * All three claims confirmed. And running it turned up why nobody noticed: the
 * TS wrapper hardcoded `node_modules/.pnpm/node_modules/.bin/tsx`, a path pnpm
 * only materialises under some hoisting settings and which does not exist in an
 * ordinary checkout. The wrapper died with "No such file or directory" on every
 * fixture, so the one tier the driver's own header claims to support could not
 * run at all. With that fixed the whole gate passes:
 *
 *     === analyzer conformance ===
 *     pass: 56  fail: 0  skip: 0  error: 0
 *
 * 8 fixtures x 7 tiers. The header's "Currently only the TypeScript tier is
 * wired in" was stale too — every wrapper works.
 *
 * This test guards the wiring, not the analyzer: the driver has to be invoked
 * by CI, and the README must not still call it planned.
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workflows = execSync("ls .github/workflows/*.yml", { cwd: ROOT, encoding: 'utf-8' })
  .trim()
  .split('\n')
  .filter(Boolean);

const allWorkflowText = workflows
  .map((w) => readFileSync(join(ROOT, w), 'utf-8'))
  .join('\n');

describe('R-219: the analyzer gate is actually run', () => {
  it('the driver exists', () => {
    // If this moves, the CI assertion below would pass while pointing at
    // nothing.
    expect(existsSync(join(ROOT, 'conformance/analyzer/run.ts'))).toBe(true);
  });

  it('every tier ships a runner wrapper', () => {
    const wrappers = execSync('ls tools/analyzer-runner/*.sh', { cwd: ROOT, encoding: 'utf-8' })
      .trim()
      .split('\n')
      .map((p) => p.replace('tools/analyzer-runner/', '').replace('.sh', ''))
      .sort();
    expect(wrappers).toEqual(['go', 'java', 'python', 'ruby', 'rust', 'ts', 'zig']);
  });

  it('the TS wrapper does not hardcode a pnpm-internal tsx path', () => {
    // The specific breakage: a path that exists only under some hoisting
    // settings, so the gate was dead in an ordinary checkout.
    const ts = readFileSync(join(ROOT, 'tools/analyzer-runner/ts.sh'), 'utf-8');
    expect(
      ts,
      'the wrapper must try the ordinary node_modules/.bin/tsx, or it dies in a normal checkout',
    ).toContain('node_modules/.bin/tsx');
    expect(
      ts,
      'the wrapper must fall back rather than exec a single hardcoded path',
    ).toMatch(/command -v tsx|for candidate in/);
  });

  it('CI invokes the driver', () => {
    expect(
      allWorkflowText,
      'conformance/analyzer/run.ts is a working seven-tier gate that no workflow runs',
    ).toContain('conformance/analyzer/run.ts');
  });

  it('the README no longer calls the driver planned', () => {
    const readme = readFileSync(join(ROOT, 'conformance/analyzer/README.md'), 'utf-8');
    expect(
      readme,
      'the README still says the driver is planned, but it exists and passes',
    ).not.toMatch(/#\s*planned/);
    expect(
      readme,
      'the README still says the driver lands once a non-TS tier ships an analyzer',
    ).not.toMatch(/Driver lands once/);
  });
});
