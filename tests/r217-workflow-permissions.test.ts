/**
 * R-217 (CL-GAP-062), the permissions half: five of nine workflows declare no
 * `permissions:` block.
 *
 * Without one, a workflow gets the repository's DEFAULT token scope. On many
 * repositories that default is read-write across contents, issues, packages and
 * more — so a job that only needs to check out code and run tests is handed a
 * token that can push commits. The blast radius of any compromised step, action
 * or installer in that job is then the whole repository rather than the job.
 *
 * `contents: read` is what every one of these jobs actually needs: they check
 * out, build, test, and upload artifacts (`actions/upload-artifact` uses the
 * artifact service, not the contents scope).
 *
 * This covers ONE of the finding's three asks. The other two — pinning each
 * third-party action by commit SHA, and pinning the elan installer by SHA-256 —
 * need the real digests, which cannot be produced offline and must not be
 * guessed. They are recorded in REMEDIATION-progress.md with the exact list.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIR = join(ROOT, '.github/workflows');

const workflows = (): string[] =>
  readdirSync(DIR).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml')).sort();

describe('R-217: every workflow declares its token scope', () => {
  it('the scan finds the workflows', () => {
    expect(workflows().length).toBeGreaterThanOrEqual(8);
  });

  it('every workflow has a top-level permissions block', () => {
    const missing = workflows().filter(
      (f) => !/^permissions:/m.test(readFileSync(join(DIR, f), 'utf8')),
    );
    expect(
      missing,
      'these run with the repository default token scope, which is broader than ' +
        'anything they need',
    ).toEqual([]);
  });

  it('no workflow grants contents: write without saying why', () => {
    const loud = workflows().filter((f) => {
      const text = readFileSync(join(DIR, f), 'utf8');
      const block = text.match(/^permissions:\n((?:[ \t]+.*\n)+)/m)?.[1] ?? '';
      if (!/contents:\s*write/.test(block)) return false;
      // A write scope is allowed, but the reason has to be written next to it.
      return !/#/.test(block);
    });
    expect(loud, 'contents: write with no comment explaining the need').toEqual([]);
  });
});
