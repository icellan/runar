/**
 * R-234 (CL-DOC-032): compilers/python/README.md claimed six input formats.
 *
 * It said the Python tier handles "**all six input formats** ... the most of
 * any compiler" and listed six rows. Nine `parser_*.py` modules ship in
 * `compilers/python/runar_compiler/frontend/` — `.runar.rb`, `.runar.zig` and
 * `.runar.java` were absent from the table, and the "most of any compiler"
 * boast was a leftover from when tiers really did differ.
 *
 * Every tier parses all nine surfaces; that is the invariant, not a Python
 * distinction. Counting the modules on disk is the check that cannot drift.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const README = join(ROOT, 'compilers/python/README.md');

describe('R-234: the Python README lists every parser module it ships', () => {
  it('names every parser_*.py module in the frontend', () => {
    const frontend = join(ROOT, 'compilers/python/runar_compiler/frontend');
    const modules = readdirSync(frontend).filter(
      (f) => f.startsWith('parser_') && f.endsWith('.py') && f !== 'parser_dispatch.py',
    );
    expect(modules.length, 'the module scan broke').toBeGreaterThan(5);

    const readme = readFileSync(README, 'utf8');
    const missing = modules.filter((m) => !readme.includes(m));
    expect(missing, 'compilers/python/README.md omits parser modules that ship').toEqual([]);
  });

  it('does not claim a six-format world', () => {
    const readme = readFileSync(README, 'utf8');
    const offenders = readme
      .split('\n')
      .filter((l) => /all six input formats/.test(l) && !/used to say|R-234/.test(l));
    expect(offenders, 'the six-format claim is back').toEqual([]);
  });
});
