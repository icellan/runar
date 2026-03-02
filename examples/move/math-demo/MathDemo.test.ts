import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'MathDemo.runar.move'), 'utf8');
const FILE_NAME = 'MathDemo.runar.move';

describe('MathDemo (Move)', () => {
  it('safediv divides correctly', () => {
    const c = TestContract.fromSource(source, { value: 100n }, FILE_NAME);
    const r = c.call('divideBy', { divisor: 5n });
    expect(r.success).toBe(true);
    expect(c.state.value).toBe(20n);
  });

  it('safediv rejects division by zero', () => {
    const c = TestContract.fromSource(source, { value: 10n }, FILE_NAME);
    const r = c.call('divideBy', { divisor: 0n });
    expect(r.success).toBe(false);
  });

  it('percentOf computes fee correctly', () => {
    const c = TestContract.fromSource(source, { value: 10000n }, FILE_NAME);
    c.call('withdrawWithFee', { amount: 1000n, feeBps: 500n });
    expect(c.state.value).toBe(8950n);
  });

  it('clamp constrains value to range', () => {
    const c = TestContract.fromSource(source, { value: 200n }, FILE_NAME);
    c.call('clampValue', { lo: 10n, hi: 100n });
    expect(c.state.value).toBe(100n);
  });

  it('sign returns -1 for negative', () => {
    const c = TestContract.fromSource(source, { value: -42n }, FILE_NAME);
    c.call('normalize');
    expect(c.state.value).toBe(-1n);
  });

  it('pow computes 2^10 = 1024', () => {
    const c = TestContract.fromSource(source, { value: 2n }, FILE_NAME);
    c.call('exponentiate', { exp: 10n });
    expect(c.state.value).toBe(1024n);
  });

  it('sqrt computes sqrt(100) = 10', () => {
    const c = TestContract.fromSource(source, { value: 100n }, FILE_NAME);
    c.call('squareRoot');
    expect(c.state.value).toBe(10n);
  });

  it('gcd computes gcd(12, 8) = 4', () => {
    const c = TestContract.fromSource(source, { value: 12n }, FILE_NAME);
    c.call('reduceGcd', { other: 8n });
    expect(c.state.value).toBe(4n);
  });

  it('mulDiv computes (1000 * 3) / 4 = 750', () => {
    const c = TestContract.fromSource(source, { value: 1000n }, FILE_NAME);
    c.call('scaleByRatio', { numerator: 3n, denominator: 4n });
    expect(c.state.value).toBe(750n);
  });

  it('log2 computes log2(1024) = 10', () => {
    const c = TestContract.fromSource(source, { value: 1024n }, FILE_NAME);
    c.call('computeLog2');
    expect(c.state.value).toBe(10n);
  });
});
