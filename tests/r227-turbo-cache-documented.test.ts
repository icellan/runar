/**
 * R-227 (GK-GAP-005): `pnpm build` in a fresh worktree reports FULL TURBO cache
 * hits, replaying logs whose paths name OTHER worktrees. The reviewer's concern
 * was that "the default documented recipe does not prove this SHA was compiled".
 *
 * The finding's own remediation says how to settle it: "Confirm turbo input
 * hashes include file contents (if so, replay is still this SHA and severity is
 * hygiene)." Measured in this worktree on `runar-ir-schema`:
 *
 *   first run                      0 cached, 1 total
 *   repeat                         1 cached, 1 total   (FULL TURBO)
 *   append one comment line        0 cached, 1 total   <- a MISS
 *   revert that line               1 cached, 1 total   <- a HIT again
 *
 * So the key is content-addressed: a hit means the inputs are byte-identical to
 * the inputs that produced those outputs, whichever worktree ran the compile.
 * The replay IS this commit's build, and the severity is hygiene — the log paths
 * look alarming and the artifact is correct.
 *
 * That is worth writing down rather than re-deriving: the next reviewer who sees
 * another worktree's path in their build log will ask the same question. This
 * test keeps the README's answer — and the `--force` recipe for when you need to
 * watch it compile — from being dropped.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const readme = () => readFileSync(join(ROOT, 'README.md'), 'utf8');

/** The paragraph the build recipe carries. */
function buildSection(): string {
  const text = readme();
  const start = text.indexOf('### Build & Test');
  expect(start, 'README has no "Build & Test" section').toBeGreaterThan(-1);
  const rest = text.slice(start + 1);
  const end = rest.indexOf('\n### ');
  return end === -1 ? rest : rest.slice(0, end);
}

describe('R-227: the shared turbo cache is explained where the build is documented', () => {
  it('the section exists and still documents pnpm build', () => {
    expect(buildSection()).toMatch(/pnpm build/);
  });

  it('warns that the turbo cache is shared across worktrees', () => {
    expect(
      buildSection(),
      'a reviewer seeing another worktree in their build log has nothing to read',
    ).toMatch(/turbo/i);
  });

  it('gives the recipe for forcing a real compile', () => {
    expect(buildSection()).toMatch(/--force/);
  });

  it('states that the cache key is content-addressed', () => {
    expect(
      buildSection(),
      'without this the reader cannot tell whether a replayed build is their SHA',
    ).toMatch(/content-address|file contents|input hash/i);
  });
});
