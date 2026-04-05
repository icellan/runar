import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BabyBearDemo.runar.ts'), 'utf8');

/**
 * Baby Bear field: p = 2013265921 = 2^31 - 2^27 + 1
 */
const P = 2013265921n;

describe('BabyBearDemo', () => {
  describe('checkAdd (bbFieldAdd)', () => {
    it('adds two small values', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkAdd', { a: 5n, b: 7n, expected: 12n });
      expect(r.success).toBe(true);
    });

    it('wraps around the field prime', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkAdd', { a: P - 1n, b: 1n, expected: 0n });
      expect(r.success).toBe(true);
    });

    it('adds zero', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkAdd', { a: 42n, b: 0n, expected: 42n });
      expect(r.success).toBe(true);
    });
  });

  describe('checkSub (bbFieldSub)', () => {
    it('subtracts two values', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkSub', { a: 10n, b: 3n, expected: 7n });
      expect(r.success).toBe(true);
    });

    it('wraps to field prime when result would be negative', () => {
      const c = TestContract.fromSource(source, {});
      // 0 - 1 = p - 1
      const r = c.call('checkSub', { a: 0n, b: 1n, expected: P - 1n });
      expect(r.success).toBe(true);
    });
  });

  describe('checkMul (bbFieldMul)', () => {
    it('multiplies two values', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkMul', { a: 6n, b: 7n, expected: 42n });
      expect(r.success).toBe(true);
    });

    it('multiplies large values with wrap', () => {
      const c = TestContract.fromSource(source, {});
      // (p-1) * 2 mod p = p - 2
      const r = c.call('checkMul', { a: P - 1n, b: 2n, expected: P - 2n });
      expect(r.success).toBe(true);
    });

    it('multiplies by zero', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkMul', { a: 12345n, b: 0n, expected: 0n });
      expect(r.success).toBe(true);
    });
  });

  describe('checkInv (bbFieldInv)', () => {
    it('inverts 1 (should return 1)', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkInv', { a: 1n });
      expect(r.success).toBe(true);
    });

    it('inverts 2', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkInv', { a: 2n });
      expect(r.success).toBe(true);
    });

    it('inverts a large value', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkInv', { a: 1000000007n });
      expect(r.success).toBe(true);
    });
  });

  describe('checkAddSubRoundtrip', () => {
    it('verifies add-sub roundtrip', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkAddSubRoundtrip', { a: 42n, b: 99n });
      expect(r.success).toBe(true);
    });
  });

  describe('checkDistributive', () => {
    it('verifies distributive law', () => {
      const c = TestContract.fromSource(source, {});
      const r = c.call('checkDistributive', { a: 5n, b: 7n, c: 11n });
      expect(r.success).toBe(true);
    });
  });
});
