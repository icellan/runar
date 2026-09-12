/**
 * R-109 — `conformance/` is a second npm root, and nothing said so.
 *
 * `pnpm-workspace.yaml` lists `packages/*` and `integration/ts`. `conformance/`
 * is neither, and it has its own `package.json` AND its own
 * `package-lock.json` with its own dependencies (`fast-check`, `tsx`,
 * `typescript`). So the only documented setup — `pnpm install && pnpm build` —
 * leaves every conformance script unrunnable, and the failure is not obvious:
 * the scripts exist, they just cannot resolve `tsx`.
 *
 * CI already knew. Three jobs in `ci.yml` run `cd conformance && npm ci`, two of
 * them with a comment explaining that conformance is not in the pnpm workspace.
 * The knowledge was in the workflow and not in the setup instructions, which is
 * the shape of an undocumented required step.
 *
 * This test requires every npm root outside the pnpm workspace to be named in
 * the setup documentation, so a third one cannot land silently. It deliberately
 * does NOT require conformance to join the workspace: changing the install
 * topology of a repo whose CI pins `npm ci` against a committed lockfile is a
 * deliberate change, not a side effect of writing docs.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';

const REPO = resolve(__dirname, '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf8');

/** Directories the pnpm workspace already installs. */
function workspaceGlobs(): string[] {
  const yml = read('pnpm-workspace.yaml');
  return [...yml.matchAll(/^\s*-\s*["']?([^"'\n]+)["']?\s*$/gm)].map((m) => m[1]!.trim());
}

function inWorkspace(dir: string, globs: string[]): boolean {
  return globs.some((g) =>
    g.endsWith('/*') ? dir.startsWith(g.slice(0, -1)) && dir.split('/').length === g.split('/').length : dir === g,
  );
}

/** Every package.json in the repo, excluding node_modules and the root. */
function packageRoots(dir = REPO, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.git' || entry === '.worktrees') continue;
    const p = join(dir, entry);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) packageRoots(p, acc);
    else if (entry === 'package.json') {
      const rel = relative(REPO, dir);
      if (rel !== '') acc.push(rel);
    }
  }
  return acc;
}

/** Documents a newcomer reads to set the repo up. */
const SETUP_DOCS = ['README.md', 'docs/getting-started.md', 'conformance/README.md'];

describe('R-109: every npm root outside the pnpm workspace is documented', () => {
  const globs = workspaceGlobs();
  const outside = packageRoots()
    .filter((d) => !inWorkspace(d, globs))
    .sort();

  it('the workspace globs parsed (an empty list would make everything "outside")', () => {
    expect(globs.length).toBeGreaterThanOrEqual(1);
  });

  it('the sweep found the known second root', () => {
    expect(outside).toContain('conformance');
  });

  for (const dir of ['conformance']) {
    it(`${dir} has its install step in the setup documentation`, () => {
      const mentioned = SETUP_DOCS.filter((doc) => {
        if (!existsSync(join(REPO, doc))) return false;
        const text = read(doc);
        return new RegExp(`cd ${dir}[^\\n]*npm (ci|install)`).test(text);
      });
      expect(
        mentioned.length,
        `${dir}/ has its own package.json and package-lock.json and is not a pnpm ` +
          `workspace member, so "pnpm install" does not install it. No setup document ` +
          `says to run "cd ${dir} && npm ci". Checked: ${SETUP_DOCS.join(', ')}`,
      ).toBeGreaterThan(0);
    });
  }

  it('no UNDOCUMENTED npm root has appeared since', () => {
    const undocumented = outside.filter((dir) => {
      if (dir === 'conformance') return false; // covered by its own case above
      return !SETUP_DOCS.some((doc) => {
        if (!existsSync(join(REPO, doc))) return false;
        return new RegExp(`cd ${dir}[^\\n]*npm (ci|install)`).test(read(doc));
      });
    });
    expect(
      undocumented,
      `these directories are npm roots outside the pnpm workspace and no setup ` +
        `document explains how to install them: ${undocumented.join(', ')}`,
    ).toEqual([]);
  });
});
