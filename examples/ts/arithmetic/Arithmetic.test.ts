import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Arithmetic.runar.ts'), 'utf8');

describe('Arithmetic', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { target: 45n });
    expect(c.state.target).toBe(45n);
  });

  it('verify accepts a=10, b=2 → target=45', () => {
    // sum=12, diff=8, prod=20, quot=5 → 45
    const c = TestContract.fromSource(source, { target: 45n });
    const r = c.call('verify', { a: 10n, b: 2n });
    expect(r.success).toBe(true);
  });

  it('verify accepts a=4, b=2 → target=18', () => {
    // sum=6, diff=2, prod=8, quot=2 → 18
    const c = TestContract.fromSource(source, { target: 18n });
    const r = c.call('verify', { a: 4n, b: 2n });
    expect(r.success).toBe(true);
  });

  it('verify rejects mismatched target', () => {
    const c = TestContract.fromSource(source, { target: 999n });
    const r = c.call('verify', { a: 10n, b: 2n });
    expect(r.success).toBe(false);
  });
});
