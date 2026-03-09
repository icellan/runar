import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'ECDemo.runar.ts'), 'utf8');

/**
 * ECDemo tests exercise every EC primitive using the TestContract interpreter.
 *
 * The interpreter performs real secp256k1 math, so we must use valid curve
 * points. We use the generator point G (scalar k=1) and 2*G as test inputs.
 *
 * G = (Gx, Gy) is the secp256k1 generator:
 *   Gx = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
 *   Gy = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
 *
 * 2*G:
 *   2Gx = C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
 *   2Gy = 1AE168FEA63DC339A3C58419466CEAE1032688D15F9C819A22CDCF72CA3E2656 (even)
 */
describe('ECDemo', () => {
  // Generator point G (1*G) — a known valid secp256k1 point
  const Gx = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
  const Gy = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';
  const mockPt = Gx + Gy; // 64-byte uncompressed point (G)

  // Known coordinates as bigint
  const GxN = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
  const GyN = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
  const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;

  // 2*G — for addition tests
  const G2x = 'C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5';
  const G2y = '1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A';
  const otherPt = G2x + G2y; // 2*G
  const G2xN = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5n;
  const G2yN = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52An;

  // 3*G — result of G + 2*G
  const G3xN = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9n;
  const G3yN = 0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672n;

  describe('checkX (ecPointX)', () => {
    it('extracts x-coordinate from G', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkX', { expectedX: GxN });
      expect(r.success).toBe(true);
    });

    it('rejects wrong x-coordinate', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkX', { expectedX: 999n });
      expect(r.success).toBe(false);
    });
  });

  describe('checkY (ecPointY)', () => {
    it('extracts y-coordinate from G', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkY', { expectedY: GyN });
      expect(r.success).toBe(true);
    });
  });

  describe('checkMakePoint (ecMakePoint)', () => {
    it('constructs a point from coordinates', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkMakePoint', {
        x: GxN, y: GyN, expectedX: GxN, expectedY: GyN,
      });
      expect(r.success).toBe(true);
    });
  });

  describe('checkOnCurve (ecOnCurve)', () => {
    it('validates that G is on the curve', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkOnCurve');
      expect(r.success).toBe(true);
    });
  });

  describe('checkAdd (ecAdd)', () => {
    it('G + 2G = 3G', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkAdd', {
        other: otherPt,
        expectedX: G3xN,
        expectedY: G3yN,
      });
      expect(r.success).toBe(true);
    });
  });

  describe('checkMul (ecMul)', () => {
    it('G * 2 = 2G', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkMul', {
        scalar: 2n,
        expectedX: G2xN,
        expectedY: G2yN,
      });
      expect(r.success).toBe(true);
    });
  });

  describe('checkMulGen (ecMulGen)', () => {
    it('ecMulGen(2) = 2G', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkMulGen', {
        scalar: 2n,
        expectedX: G2xN,
        expectedY: G2yN,
      });
      expect(r.success).toBe(true);
    });
  });

  describe('checkNegate (ecNegate)', () => {
    it('negates G: y becomes P - Gy', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const expectedNegY = EC_P - GyN;
      const r = c.call('checkNegate', { expectedNegY });
      expect(r.success).toBe(true);
    });
  });

  describe('checkNegateRoundtrip', () => {
    it('double negation returns original', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkNegateRoundtrip');
      expect(r.success).toBe(true);
    });
  });

  describe('checkModReduce (ecModReduce)', () => {
    it('reduces positive value', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkModReduce', {
        value: 17n, modulus: 5n, expected: 2n,
      });
      expect(r.success).toBe(true);
    });

    it('reduces negative value to non-negative', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkModReduce', {
        value: -3n, modulus: 5n, expected: 2n,
      });
      expect(r.success).toBe(true);
    });
  });

  describe('checkEncodeCompressed (ecEncodeCompressed)', () => {
    it('compresses G to 33-byte key (y is even → 02 prefix)', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      // Gy is even, so prefix is 02
      const expected = '02' + Gx;
      const r = c.call('checkEncodeCompressed', { expected });
      expect(r.success).toBe(true);
    });
  });

  describe('checkMulIdentity', () => {
    it('1 * G = G', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkMulIdentity');
      expect(r.success).toBe(true);
    });
  });

  describe('checkAddOnCurve', () => {
    it('G + 2G is on curve', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkAddOnCurve', { other: otherPt });
      expect(r.success).toBe(true);
    });
  });

  describe('checkMulGenOnCurve', () => {
    it('42 * G is on curve', () => {
      const c = TestContract.fromSource(source, { pt: mockPt });
      const r = c.call('checkMulGenOnCurve', { scalar: 42n });
      expect(r.success).toBe(true);
    });
  });
});
