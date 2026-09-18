import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';

/**
 * R-132 / CL-DOC-029 — `packages/decompiler` was absent from CLAUDE.md's
 * repository-structure map.
 *
 * It is not a scratch directory: 29 TypeScript source files, a dedicated CI job
 * (`decompiler-roundtrip` in .github/workflows/ci.yml), and a wired CLI command
 * (`runar decompile`, bin.ts:109). A shipped, CI-gated component the governing
 * document does not acknowledge is a component reviewers do not review — and
 * this review found it only because a worker happened to walk `packages/`.
 *
 * The fix is the map entry. The guard is this test, and it is deliberately
 * wider than the one finding: EVERY directory under `packages/` must appear in
 * the map, so the next package to land cannot go missing the same way. Measured
 * when it was written: 13 of the 14 packages were listed; `decompiler` was the
 * only hole.
 */

const REPO = resolve(__dirname, '../../../..');
const CLAUDE_MD = resolve(REPO, 'CLAUDE.md');

/** The fenced ``` block that draws the repository tree. */
function repositoryMap(): string {
  const text = readFileSync(CLAUDE_MD, 'utf8');
  const start = text.indexOf('## Repository Structure');
  expect(start, 'CLAUDE.md lost its "## Repository Structure" section').toBeGreaterThan(-1);
  const fenceOpen = text.indexOf('```', start);
  const fenceClose = text.indexOf('```', fenceOpen + 3);
  expect(fenceClose, 'the repository-structure fence is unterminated').toBeGreaterThan(fenceOpen);
  return text.slice(fenceOpen + 3, fenceClose);
}

/** Real packages: a directory under packages/ carrying a manifest. */
function packageDirs(): string[] {
  const dir = resolve(REPO, 'packages');
  return readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory() && !e.name.startsWith('.'))
    .map((e) => e.name)
    .filter((name) =>
      ['package.json', 'go.mod', 'Cargo.toml', 'build.gradle', 'pyproject.toml', 'build.zig']
        .some((m) => existsSync(join(dir, name, m))),
    )
    .sort();
}

describe('R-132 the repository map names every package', () => {
  it('finds a non-trivial set of packages (a silently empty scan proves nothing)', () => {
    expect(packageDirs().length).toBeGreaterThanOrEqual(10);
  });

  it('every package under packages/ appears in the map', () => {
    const map = repositoryMap();
    const missing = packageDirs().filter((name) => !new RegExp(`(^|\\s)${name}/`, 'm').test(map));
    expect(
      missing,
      `CLAUDE.md's repository-structure map omits: ${missing.join(', ')}. ` +
        `A shipped component the governing document does not list is one reviewers do not review.`,
    ).toEqual([]);
  });

  it('decompiler specifically — the one that was missing', () => {
    expect(repositoryMap()).toMatch(/(^|\s)decompiler\//m);
  });

  it('the decompiler is still CI-gated and CLI-wired, so the entry is not decoration', () => {
    const ci = readFileSync(resolve(REPO, '.github/workflows/ci.yml'), 'utf8');
    expect(ci, 'the decompiler-roundtrip job is gone — re-check the map entry').toMatch(
      /decompiler-roundtrip:/,
    );
    const bin = readFileSync(resolve(REPO, 'packages/runar-cli/src/bin.ts'), 'utf8');
    expect(bin).toMatch(/\.command\('decompile'\)/);
  });
});
