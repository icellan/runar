/**
 * GK-DOC-002: docs/formats/README.md listed eight extensions (no
 * `.runar.java`) and restricted several formats to compiler subsets ("Parsed
 * by the TypeScript and Zig compilers", "Go and Python compilers", "Rust and
 * Python compilers"). CLAUDE.md invariant 1 says all seven compilers parse all
 * nine extensions, and CI's parser-only matrix enforces it.
 *
 * Proves: the extension table has all nine rows, none restricted to a
 * compiler subset, and the page points at the frontend-parity invariant.
 * Does not prove: that every parser accepts every fixture (the CI
 * `--parser-only` step does that).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DOC = readFileSync(join(ROOT, 'docs', 'formats', 'README.md'), 'utf8');
const EXTS = ['ts', 'sol', 'move', 'go', 'rs', 'py', 'zig', 'rb', 'java'];

describe('GK-DOC-002: the formats README lists all nine frontends for all seven compilers', () => {
  it('has a table row for every one of the nine extensions', () => {
    for (const ext of EXTS) {
      expect(DOC, `no table row for .runar.${ext}`).toMatch(
        new RegExp('^\\| `\\.runar\\.' + ext + '` \\|', 'm'),
      );
    }
  });

  it('does not restrict a format to a compiler subset', () => {
    for (const stale of [
      'Parsed by the TypeScript and Zig compilers',
      'Go and Python compilers',
      'Rust and Python compilers',
      'seven **experimental** alternative',
    ]) {
      expect(DOC, `stale restriction: "${stale}"`).not.toContain(stale);
    }
  });

  it('points at the frontend-parity invariant and the parser-only CI step', () => {
    expect(DOC).toMatch(/--parser-only/);
    expect(DOC).toMatch(/CLAUDE\.md/);
  });

  it('draws .runar.java into the pipeline diagram', () => {
    const diagram = DOC.slice(DOC.indexOf('```\n  .runar.ts'), DOC.indexOf('ContractNode AST ──►') + 200);
    expect(diagram).toContain('.runar.java');
  });
});
