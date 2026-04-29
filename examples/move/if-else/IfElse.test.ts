import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'IfElse.runar.move'), 'utf8');
const FILE_NAME = 'IfElse.runar.move';

describe('IfElse (Move)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { limit: 5n }, FILE_NAME);
    expect(c.state.limit).toBe(5n);
  });

  it('passes on the true branch (value + limit > 0)', () => {
    const c = TestContract.fromSource(source, { limit: 5n }, FILE_NAME);
    expect(c.call('check', { value: 3n, mode: true }).success).toBe(true);
  });

  it('passes on the false branch (value - limit > 0)', () => {
    const c = TestContract.fromSource(source, { limit: 5n }, FILE_NAME);
    expect(c.call('check', { value: 20n, mode: false }).success).toBe(true);
  });

  it('rejects when neither branch yields a positive result', () => {
    const c = TestContract.fromSource(source, { limit: 5n }, FILE_NAME);
    expect(c.call('check', { value: 1n, mode: false }).success).toBe(false);
  });
});
