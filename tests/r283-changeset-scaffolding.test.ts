/**
 * R-283 (CL-GAP-071): `.changeset/` is scaffolded and nothing consumes it.
 *
 * The finding says "no changeset files exist"; one does now
 * (`anys-oppushtx-binding.md`, 2026-09-01), which makes the situation worse
 * rather than better: a contributor followed the convention and their changeset
 * does nothing, because `@changesets/cli` is a devDependency that no script,
 * workflow or hook ever invokes. The real release flow is
 * `scripts/bump-version.sh` + `release.sh` + `publish-all.sh`.
 *
 * Rather than delete a directory holding a good description of a real change,
 * the README now says plainly that it is not wired in. This test keeps those
 * two facts in agreement: while no script invokes the CLI, the README must say
 * so — and when someone wires it up, this fails until the README is rewritten.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function invokesChangesetCli(): boolean {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
    scripts?: Record<string, string>;
  };
  if (Object.values(pkg.scripts ?? {}).some((s) => /\bchangeset\b/.test(s))) return true;

  const wfDir = join(ROOT, '.github', 'workflows');
  if (existsSync(wfDir)) {
    for (const f of readdirSync(wfDir)) {
      if (/\bchangeset (version|publish)\b/.test(readFileSync(join(wfDir, f), 'utf8'))) return true;
    }
  }
  const scriptsDir = join(ROOT, 'scripts');
  if (existsSync(scriptsDir)) {
    for (const f of readdirSync(scriptsDir)) {
      if (/\bchangeset (version|publish)\b/.test(readFileSync(join(scriptsDir, f), 'utf8'))) return true;
    }
  }
  return false;
}

describe('R-283: the changeset README matches whether changesets is wired in', () => {
  it('says it is not the release flow while nothing invokes the CLI', () => {
    const readme = readFileSync(join(ROOT, '.changeset', 'README.md'), 'utf8');
    const wired = invokesChangesetCli();

    if (!wired) {
      expect(
        readme.includes('NOT the release flow'),
        'nothing invokes @changesets/cli, so .changeset/README.md must say so — ' +
          'otherwise a contributor writes a changeset that does nothing',
      ).toBe(true);
    } else {
      expect(
        readme.includes('NOT the release flow'),
        'a script now invokes the changesets CLI; rewrite .changeset/README.md, ' +
          'which still says the directory is not wired in',
      ).toBe(false);
    }
  });
});
