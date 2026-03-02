import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'MathDemo.runar.ts'), 'utf8');

describe('MathDemo', () => {
  // --- safediv ---
  describe('divideBy (safediv)', () => {
    it('divides value evenly', () => {
      const c = TestContract.fromSource(source, { value: 100n });
      const r = c.call('divideBy', { divisor: 5n });
      expect(r.success).toBe(true);
      expect(c.state.value).toBe(20n);
    });

    it('truncates toward zero', () => {
      const c = TestContract.fromSource(source, { value: 7n });
      c.call('divideBy', { divisor: 2n });
      expect(c.state.value).toBe(3n);
    });

    it('rejects division by zero', () => {
      const c = TestContract.fromSource(source, { value: 10n });
      const r = c.call('divideBy', { divisor: 0n });
      expect(r.success).toBe(false);
    });
  });

  // --- percentOf ---
  describe('withdrawWithFee (percentOf)', () => {
    it('deducts amount plus fee in basis points', () => {
      const c = TestContract.fromSource(source, { value: 10000n });
      // Withdraw 1000 with 500 bps (5%) fee → fee = 50, total = 1050
      const r = c.call('withdrawWithFee', { amount: 1000n, feeBps: 500n });
      expect(r.success).toBe(true);
      expect(c.state.value).toBe(8950n);
    });

    it('rejects if insufficient balance', () => {
      const c = TestContract.fromSource(source, { value: 100n });
      const r = c.call('withdrawWithFee', { amount: 100n, feeBps: 1000n });
      expect(r.success).toBe(false);
    });

    it('handles zero fee', () => {
      const c = TestContract.fromSource(source, { value: 1000n });
      const r = c.call('withdrawWithFee', { amount: 500n, feeBps: 0n });
      expect(r.success).toBe(true);
      expect(c.state.value).toBe(500n);
    });
  });

  // --- clamp ---
  describe('clampValue (clamp)', () => {
    it('clamps value below minimum up to lo', () => {
      const c = TestContract.fromSource(source, { value: 3n });
      c.call('clampValue', { lo: 10n, hi: 100n });
      expect(c.state.value).toBe(10n);
    });

    it('clamps value above maximum down to hi', () => {
      const c = TestContract.fromSource(source, { value: 200n });
      c.call('clampValue', { lo: 10n, hi: 100n });
      expect(c.state.value).toBe(100n);
    });

    it('leaves value in range unchanged', () => {
      const c = TestContract.fromSource(source, { value: 50n });
      c.call('clampValue', { lo: 10n, hi: 100n });
      expect(c.state.value).toBe(50n);
    });
  });

  // --- sign ---
  describe('normalize (sign)', () => {
    it('returns 1 for positive', () => {
      const c = TestContract.fromSource(source, { value: 42n });
      c.call('normalize');
      expect(c.state.value).toBe(1n);
    });

    it('returns -1 for negative', () => {
      const c = TestContract.fromSource(source, { value: -7n });
      c.call('normalize');
      expect(c.state.value).toBe(-1n);
    });

    it('returns 0 for zero', () => {
      const c = TestContract.fromSource(source, { value: 0n });
      c.call('normalize');
      expect(c.state.value).toBe(0n);
    });
  });

  // --- pow ---
  describe('exponentiate (pow)', () => {
    it('computes 2^10 = 1024', () => {
      const c = TestContract.fromSource(source, { value: 2n });
      c.call('exponentiate', { exp: 10n });
      expect(c.state.value).toBe(1024n);
    });

    it('computes x^0 = 1', () => {
      const c = TestContract.fromSource(source, { value: 99n });
      c.call('exponentiate', { exp: 0n });
      expect(c.state.value).toBe(1n);
    });

    it('computes x^1 = x', () => {
      const c = TestContract.fromSource(source, { value: 7n });
      c.call('exponentiate', { exp: 1n });
      expect(c.state.value).toBe(7n);
    });

    it('computes 3^5 = 243', () => {
      const c = TestContract.fromSource(source, { value: 3n });
      c.call('exponentiate', { exp: 5n });
      expect(c.state.value).toBe(243n);
    });
  });

  // --- sqrt ---
  describe('squareRoot (sqrt)', () => {
    it('computes sqrt(100) = 10', () => {
      const c = TestContract.fromSource(source, { value: 100n });
      c.call('squareRoot');
      expect(c.state.value).toBe(10n);
    });

    it('computes sqrt(0) = 0', () => {
      const c = TestContract.fromSource(source, { value: 0n });
      c.call('squareRoot');
      expect(c.state.value).toBe(0n);
    });

    it('computes floor sqrt of non-perfect square', () => {
      const c = TestContract.fromSource(source, { value: 10n });
      c.call('squareRoot');
      expect(c.state.value).toBe(3n);
    });

    it('computes sqrt(1000000) = 1000', () => {
      const c = TestContract.fromSource(source, { value: 1000000n });
      c.call('squareRoot');
      expect(c.state.value).toBe(1000n);
    });
  });

  // --- gcd ---
  describe('reduceGcd (gcd)', () => {
    it('computes gcd(12, 8) = 4', () => {
      const c = TestContract.fromSource(source, { value: 12n });
      c.call('reduceGcd', { other: 8n });
      expect(c.state.value).toBe(4n);
    });

    it('computes gcd(7, 13) = 1 (coprime)', () => {
      const c = TestContract.fromSource(source, { value: 7n });
      c.call('reduceGcd', { other: 13n });
      expect(c.state.value).toBe(1n);
    });

    it('computes gcd(0, 5) = 5', () => {
      const c = TestContract.fromSource(source, { value: 0n });
      c.call('reduceGcd', { other: 5n });
      expect(c.state.value).toBe(5n);
    });
  });

  // --- mulDiv ---
  describe('scaleByRatio (mulDiv)', () => {
    it('computes (1000 * 3) / 4 = 750', () => {
      const c = TestContract.fromSource(source, { value: 1000n });
      c.call('scaleByRatio', { numerator: 3n, denominator: 4n });
      expect(c.state.value).toBe(750n);
    });

    it('handles large intermediate products', () => {
      const c = TestContract.fromSource(source, { value: 1000000n });
      c.call('scaleByRatio', { numerator: 999999n, denominator: 1000000n });
      // (1000000 * 999999) / 1000000 = 999999
      expect(c.state.value).toBe(999999n);
    });
  });

  // --- log2 ---
  describe('computeLog2 (log2)', () => {
    it('computes log2(1) = 0', () => {
      const c = TestContract.fromSource(source, { value: 1n });
      c.call('computeLog2');
      expect(c.state.value).toBe(0n);
    });

    it('computes log2(1024) = 10', () => {
      const c = TestContract.fromSource(source, { value: 1024n });
      c.call('computeLog2');
      expect(c.state.value).toBe(10n);
    });

    it('computes floor log2 for non-powers', () => {
      const c = TestContract.fromSource(source, { value: 100n });
      c.call('computeLog2');
      // floor(log2(100)) = 6
      expect(c.state.value).toBe(6n);
    });
  });

  // --- composition ---
  describe('composing multiple math operations', () => {
    it('chains operations correctly', () => {
      const c = TestContract.fromSource(source, { value: 10000n });
      // Withdraw 2000 with 250 bps (2.5%) fee → fee=50, total=2050 → 7950
      c.call('withdrawWithFee', { amount: 2000n, feeBps: 250n });
      expect(c.state.value).toBe(7950n);
      // Divide by 3 → 2650
      c.call('divideBy', { divisor: 3n });
      expect(c.state.value).toBe(2650n);
      // Clamp to [0, 2000] → 2000
      c.call('clampValue', { lo: 0n, hi: 2000n });
      expect(c.state.value).toBe(2000n);
    });
  });
});
