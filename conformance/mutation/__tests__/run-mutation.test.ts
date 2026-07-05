import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyMutant, revertMutant, type Mutant } from '../run-mutation.js';

describe('applyMutant / revertMutant (exact, unique find/replace)', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'runar-mut-'));
    file = join(dir, 'sample.ts');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const mk = (find: string, replace: string): Mutant => ({
    id: 't',
    file, // absolute here; harness passes repo-relative + a root
    find,
    replace,
    class: 'swapped operands',
    stage: 'emit',
    expectCaughtBy: [],
  });

  it('applies a unique find, then reverts to the exact original', () => {
    const original = "const x = a + b;\nconst y = c - d;\n";
    writeFileSync(file, original);

    applyMutant(mk('a + b', 'a - b'), file);
    expect(readFileSync(file, 'utf-8')).toBe("const x = a - b;\nconst y = c - d;\n");

    revertMutant(mk('a + b', 'a - b'), file);
    expect(readFileSync(file, 'utf-8')).toBe(original);
  });

  it('throws when the find string is absent', () => {
    writeFileSync(file, 'nothing to see here\n');
    expect(() => applyMutant(mk('missing', 'x'), file)).toThrow(/not found|0 time/i);
  });

  it('throws when the find string is not unique', () => {
    writeFileSync(file, 'dup\ndup\n');
    expect(() => applyMutant(mk('dup', 'x'), file)).toThrow(/2 time|unique/i);
  });

  it('revert throws if the mutated string is no longer uniquely present', () => {
    writeFileSync(file, 'alpha\n');
    applyMutant(mk('alpha', 'beta'), file);
    // Corrupt the file so revert can no longer find a unique replacement.
    writeFileSync(file, 'beta beta\n');
    expect(() => revertMutant(mk('alpha', 'beta'), file)).toThrow(/2 time|unique/i);
  });
});
