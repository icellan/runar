/**
 * The `Decompiler coverage matrix` CI step runs scripts/coverage-matrix.ts.
 * That script used to have no failure path at all — `grep -nE 'exit|throw'`
 * matched nothing in its 182 lines — so the step reported green whatever the
 * matrix said, and the checked-in coverage.json silently went 7 rows stale.
 *
 * These tests pin the failure path itself: `--check` compares the freshly
 * computed matrix against a recorded one and exits non-zero on any drift.
 * Each case spawns the real script, so each pays a full matrix run (~10s).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, '..');
const SCRIPT = resolve(PKG_ROOT, 'scripts', 'coverage-matrix.ts');
const COVERAGE = resolve(PKG_ROOT, 'coverage.json');

function runCheck(expectedPath?: string) {
  const args = [SCRIPT, '--check'];
  if (expectedPath) args.push(expectedPath);
  const r = spawnSync('npx', ['tsx', ...args], {
    cwd: PKG_ROOT,
    encoding: 'utf8',
    env: process.env,
  });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}

describe('coverage-matrix --check', () => {
  // Control. The gate is only worth having if a healthy tree passes it; if
  // this reddens, the check is over-strict rather than the corpus regressed.
  it('exits 0 when the checked-in coverage.json is current', () => {
    const r = runCheck();
    expect(r.status, `coverage.json is stale — regenerate and commit it\n${r.out}`).toBe(0);
  }, 300_000);

  it('exits non-zero on a changed / removed / extra row', () => {
    const current = JSON.parse(readFileSync(COVERAGE, 'utf8')) as {
      rows: { id: string; outcome: string; recoveryPath?: string }[];
      summary: Record<string, number>;
    };
    expect(current.rows.length, 'need at least 2 rows to mutate').toBeGreaterThan(1);
    const changedId = current.rows[0]!.id;
    const removedId = current.rows[1]!.id;
    const mutated = structuredClone(current);
    // One of each drift shape the check has to catch.
    mutated.rows[0]!.outcome = 'compile-error';
    mutated.rows.splice(1, 1);
    mutated.rows.push({ id: 'ghost/Ghost', outcome: 'byte-match', recoveryPath: 'template' });

    const dir = mkdtempSync(join(tmpdir(), 'runar-cov-'));
    const path = join(dir, 'mutated.json');
    writeFileSync(path, JSON.stringify(mutated, null, 2) + '\n', 'utf8');

    const r = runCheck(path);
    expect(r.status, `expected drift to be reported\n${r.out}`).not.toBe(0);
    expect(r.out).toContain(changedId);
    expect(r.out).toContain(removedId);
    expect(r.out).toContain('ghost/Ghost');
  }, 300_000);

  it('exits non-zero when there is no recorded matrix to compare against', () => {
    const r = runCheck(join(mkdtempSync(join(tmpdir(), 'runar-cov-')), 'absent.json'));
    expect(r.status, `expected a missing baseline to fail\n${r.out}`).not.toBe(0);
  }, 300_000);
});
