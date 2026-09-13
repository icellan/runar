/**
 * R-231 (CL-DOC-003): compilers/rust/README.md named four of the surfaces its
 * frontend parses.
 *
 * The README said the compiler accepts "multi-format source files (.runar.sol,
 * .runar.move, .runar.rs, .runar.py)". `parser::parse_source`
 * (compilers/rust/src/frontend/parser.rs) dispatches eight non-TypeScript
 * extensions — `.go`, `.rb`, `.zig` and `.java` were missing from the list.
 *
 * That understates the project's headline invariant: every tier parses all nine
 * surfaces, for every fixture, no exceptions. A list that stops at five makes
 * the guarantee look smaller than it is, and this README is what a Rust-tier
 * contributor reads first.
 *
 * The test derives the set from the dispatcher's own literals rather than from
 * a hand-kept list, so the next surface added to parse_source has to reach the
 * docs before this goes green again.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('R-231: the Rust README lists every surface the frontend parses', () => {
  it('names every extension parse_source dispatches', () => {
    const parser = readFileSync(
      join(ROOT, 'compilers/rust/src/frontend/parser.rs'),
      'utf8',
    );
    const extensions = [
      ...new Set([...parser.matchAll(/"(\.runar\.[a-z]+)"/g)].map((m) => m[1]!)),
    ];
    expect(extensions.length, 'the extension scan broke').toBeGreaterThan(5);

    const readme = readFileSync(join(ROOT, 'compilers/rust/README.md'), 'utf8');
    const missing = extensions.filter((e) => !readme.includes(e));
    expect(missing, 'compilers/rust/README.md omits surfaces the frontend parses').toEqual([]);
  });
});
