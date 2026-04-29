import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Arithmetic.runar.move'), 'utf8');
const FILE_NAME = 'Arithmetic.runar.move';

describe('Arithmetic (Move)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { target: 45n }, FILE_NAME);
    expect(c.state.target).toBe(45n);
  });

  it('verify accepts a=10, b=2 → target=45', () => {
    const c = TestContract.fromSource(source, { target: 45n }, FILE_NAME);
    expect(c.call('verify', { a: 10n, b: 2n }).success).toBe(true);
  });

  it('verify accepts a=4, b=2 → target=18', () => {
    const c = TestContract.fromSource(source, { target: 18n }, FILE_NAME);
    expect(c.call('verify', { a: 4n, b: 2n }).success).toBe(true);
  });

  it('verify rejects mismatched target', () => {
    const c = TestContract.fromSource(source, { target: 999n }, FILE_NAME);
    expect(c.call('verify', { a: 10n, b: 2n }).success).toBe(false);
  });
});
