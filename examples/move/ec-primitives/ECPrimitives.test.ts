import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'ECPrimitives.runar.move'), 'utf8');
const FILE_NAME = 'ECPrimitives.runar.move';

describe('ECPrimitives (Move)', () => {
  const Gx = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
  const Gy = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';
  const mockPt = Gx + Gy;

  const GxN = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
  const GyN = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
  const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;

  const G2x = 'C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5';
  const G2y = '1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A';
  const otherPt = G2x + G2y;
  const G2xN = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5n;
  const G2yN = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52An;
  const G3xN = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9n;
  const G3yN = 0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672n;

  it('checkX extracts x of G', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkX', { expectedX: GxN }).success).toBe(true);
  });

  it('checkY extracts y of G', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkY', { expectedY: GyN }).success).toBe(true);
  });

  it('checkOnCurve validates G', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkOnCurve').success).toBe(true);
  });

  it('checkNegateY: P - Gy', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkNegateY', { expectedNegY: EC_P - GyN }).success).toBe(true);
  });

  it('checkAdd: G + 2G = 3G', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkAdd', { other: otherPt, expectedX: G3xN, expectedY: G3yN }).success).toBe(true);
  });

  it('checkMul: G * 2 = 2G', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkMul', { scalar: 2n, expectedX: G2xN, expectedY: G2yN }).success).toBe(true);
  });

  it('checkMulGen: ecMulGen(2) = 2G', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkMulGen', { scalar: 2n, expectedX: G2xN, expectedY: G2yN }).success).toBe(true);
  });

  it('checkMakePoint roundtrip', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkMakePoint', { x: GxN, y: GyN, expectedX: GxN, expectedY: GyN }).success).toBe(true);
  });

  it('checkEncodeCompressed of G has 02 prefix (Gy is even)', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkEncodeCompressed', { expected: '02' + Gx }).success).toBe(true);
  });

  it('checkMulIdentity: 1 * G = G', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkMulIdentity').success).toBe(true);
  });

  it('checkNegateRoundtrip: --G = G', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkNegateRoundtrip').success).toBe(true);
  });

  it('checkAddOnCurve: G + 2G is on curve', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkAddOnCurve', { other: otherPt }).success).toBe(true);
  });

  it('checkMulGenOnCurve: 42 * G is on curve', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkMulGenOnCurve', { scalar: 42n }).success).toBe(true);
  });

  it('checkModReduce reduces positive value', () => {
    const c = TestContract.fromSource(source, { pt: mockPt }, FILE_NAME);
    expect(c.call('checkModReduce', { value: 17n, modulus: 5n, expected: 2n }).success).toBe(true);
  });
});
