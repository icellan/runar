/**
 * R-253 (CL-DOC-014): the fuzz-regressions README's entry table lists four of
 * the six entries, and describes an oracle-kind limitation that a later entry
 * already superseded.
 *
 * The table said "Current entries" and named the four shift/bitwise entries from
 * PR #141, followed by "All four come from the shift/bitwise semantics bug".
 * Two more had landed since:
 *
 *   2026-08-06-branch-k1-empty-pad-guard-bypass   (oracle: execute)
 *   2026-08-17-shift-nonminimal-zero-numeric-consume (oracle: tri-modal)
 *
 * and the second one is the interesting half. The prose said findings from
 * oracles other than `execute` "are not replayable here yet; add a second
 * `oracle` kind to `replay.ts` when the first such finding needs pinning" — that
 * second kind exists, `replay.ts` documents it, and an entry uses it. A reader
 * following the README would have concluded a consensus-verdict regression
 * could not be pinned, and skipped pinning one.
 *
 * This corpus is the place where fund-losing divergences go to stay fixed, so a
 * table that undercounts it by a third is not a typo.
 *
 * The test derives both the entry list and the oracle kinds from the corpus on
 * disk, so the next entry has to reach the README.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CORPUS = join(ROOT, 'conformance/fuzz-regressions');
const ENTRIES = join(CORPUS, 'entries');

function entryIds(): string[] {
  return readdirSync(ENTRIES, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

function oracleKinds(): string[] {
  return [
    ...new Set(
      entryIds().map(
        (id) =>
          JSON.parse(readFileSync(join(ENTRIES, id, 'entry.json'), 'utf8')).oracle as string,
      ),
    ),
  ].sort();
}

const readme = () => readFileSync(join(CORPUS, 'README.md'), 'utf8');

describe('R-253: the fuzz-regressions README matches the corpus', () => {
  it('the corpus scan is not vacuous', () => {
    expect(entryIds().length).toBeGreaterThanOrEqual(6);
    expect(oracleKinds().length).toBeGreaterThanOrEqual(2);
  });

  it('lists every entry that ships', () => {
    const text = readme();
    const missing = entryIds().filter((id) => !text.includes(id));
    expect(missing, 'entries in the corpus that the README does not list').toEqual([]);
  });

  it('names every oracle kind the corpus actually uses', () => {
    const text = readme();
    const missing = oracleKinds().filter((k) => !text.includes(`\`${k}\``));
    expect(missing, 'oracle kinds used by an entry but absent from the README').toEqual([]);
  });

  it('does not claim a kind other than `execute` cannot be pinned yet', () => {
    const offenders = readme()
      .split('\n')
      .filter((l) => /not replayable here yet/.test(l) && !/used to say|R-253/.test(l));
    expect(
      offenders,
      'the README still tells the reader a non-execute finding cannot be pinned, ' +
        'while an entry in the corpus already is',
    ).toEqual([]);
  });
});
