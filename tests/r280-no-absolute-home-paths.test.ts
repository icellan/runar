/**
 * R-280 (CL-GAP-067): the Zig benchmark README hardcodes someone's home
 * directory — `cd /Users/satchmo/code/runar` — in every one of its run
 * instructions.
 *
 * Nobody else has that path, so every command in the file fails on the first
 * line for every reader. The benchmarks themselves are fine: the harness
 * (`compilers/zig/scripts/benchmark_compare.py`) is present and the contract
 * lists still compile. What does not work is the only documentation for
 * running them.
 *
 * The scan is repo-wide over checked-in Markdown rather than aimed at the one
 * file, because a hardcoded home directory is a mistake that arrives by
 * copy-paste from a terminal and lands anywhere. Untracked working files are
 * excluded: they are scratch, not documentation.
 *
 * The finding's other halves are recorded, not fixed: the benchmarks are still
 * un-automated (nothing in CI runs them, and making them a CI job is a
 * performance-budget decision, not a docs fix), and the directory was last
 * touched 2026-03-22.
 */

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Markdown files git actually tracks. */
function trackedMarkdown(): string[] {
  const out = execFileSync('git', ['ls-files', '*.md'], { cwd: ROOT, encoding: 'utf-8' });
  return out.split('\n').filter(Boolean);
}

/** `/Users/<name>/…` or `/home/<name>/…` — a path only its author has. */
const HOME_PATH = /(^|[\s"'`(=])(\/Users\/[a-z][a-z0-9._-]*|\/home\/[a-z][a-z0-9._-]*)\//gim;

describe('R-280: no checked-in doc hardcodes a developer home directory', () => {
  it('the scan finds the repo markdown', () => {
    const files = trackedMarkdown();
    expect(files.length, 'git ls-files returned no markdown').toBeGreaterThan(20);
    expect(files).toContain('compilers/zig/benchmarks/README.md');
  });

  it('every tracked markdown file uses repo-relative paths', () => {
    const offenders: string[] = [];
    for (const rel of trackedMarkdown()) {
      const text = readFileSync(join(ROOT, rel), 'utf-8');
      for (const m of text.matchAll(HOME_PATH)) {
        const line = text.slice(0, m.index).split('\n').length;
        offenders.push(`${rel}:${line}: ${m[2]}/…`);
      }
    }
    expect(
      offenders,
      'these instructions only work on the machine they were written on',
    ).toEqual([]);
  });
});
