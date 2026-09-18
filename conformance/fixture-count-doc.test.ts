/**
 * R-252 (CL-DOC-013): conformance/README.md claimed "64 fixtures" while the
 * suite held 78.
 *
 * The README even names the command that settles it —
 * `find tests -name source.json | wc -l` — and calls that directory "the
 * authoritative list". The number beside it had simply not been re-run. A
 * reader comparing a local run's fixture count against the README would have
 * concluded 14 fixtures were missing.
 *
 * This test runs that command's equivalent and requires the sentence to agree,
 * so the next fixture added updates the prose or fails here.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = resolve(dirname(fileURLToPath(import.meta.url)));

describe('R-252: the README fixture count matches the corpus', () => {
  it('agrees with the number of tests/*/source.json files', () => {
    const actual = readdirSync(join(HERE, 'tests')).filter((d) =>
      existsSync(join(HERE, 'tests', d, 'source.json')),
    ).length;

    const readme = readFileSync(join(HERE, 'README.md'), 'utf8');
    const claim = readme.match(/contains \*\*(\d+) fixtures\*\* under `tests\/`/);

    expect(claim, 'the fixture-count sentence has moved or changed shape').not.toBeNull();
    expect(Number(claim![1]), `README says ${claim![1]} fixtures; tests/ holds ${actual}`)
      .toBe(actual);
  });
});
