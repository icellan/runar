/**
 * Test the off-chain Groth16 verifier.
 *
 * Creates a synthetic valid proof using known scalar multiples of the
 * generators, then verifies the pairing equation holds.
 */

import { describe, it, expect } from 'vitest';
import { verifyGroth16 } from '../groth16/verify.js';
import { g1Mul } from '../bn254/g1.js';
import { g2Mul } from '../bn254/g2.js';
import { G1_X, G1_Y, G2_X_C0, G2_X_C1, G2_Y_C0, G2_Y_C1, R } from '../bn254/constants.js';
import type { VerificationKey, Groth16Proof, G1Point, G2Point } from '../types.js';

const G1_GEN: G1Point = { x: G1_X, y: G1_Y };
const G2_GEN: G2Point = { x: { c0: G2_X_C0, c1: G2_X_C1 }, y: { c0: G2_Y_C0, c1: G2_Y_C1 } };

describe('Groth16 off-chain verifier', () => {
  /**
   * Construct a trivial valid Groth16 proof for a circuit with 0 public inputs.
   *
   * The verification equation is:
   *   e(A, B) = e(alpha, beta) · e(IC[0], gamma) · e(C, delta)
   *
   * Choose random scalars a, b and set:
   *   alpha = [α]G1, beta = [β]G2, gamma = G2, delta = G2
   *   IC[0] = [ic0]G1
   *   A = [a]G1, B = [b]G2
   *   C must satisfy: e(C, delta) = e(A,B) / (e(alpha,beta) * e(IC[0],gamma))
   *
   * Since delta = G2, C = [a*b - α*β - ic0]G1
   */
  it('verifies a synthetic proof (0 public inputs)', () => {
    const alpha_s = 7n;
    const beta_s = 11n;
    const gamma_s = 1n; // gamma = G2
    const delta_s = 1n; // delta = G2
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);

    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);

    // C = [a*b - α*β - ic0] G1
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };
    const proof: Groth16Proof = { a: A, b: B, c: C };

    expect(verifyGroth16(vk, proof, [])).toBe(true);
  });

  it('rejects a tampered proof (0 public inputs)', () => {
    const alpha = g1Mul(G1_GEN, 7n);
    const beta = g2Mul(G2_GEN, 11n);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, 5n);

    const A = g1Mul(G1_GEN, 13n);
    const B = g2Mul(G2_GEN, 17n);
    const c_scalar = ((13n * 17n - 7n * 11n - 5n) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };
    // Tamper: use wrong A
    const badA = g1Mul(G1_GEN, 999n);
    const badProof: Groth16Proof = { a: badA, b: B, c: C };

    expect(verifyGroth16(vk, badProof, [])).toBe(false);
  });

  it('verifies a synthetic proof with 1 public input', () => {
    const alpha_s = 3n;
    const beta_s = 5n;
    const ic0_s = 2n;
    const ic1_s = 7n;
    const a_s = 19n;
    const b_s = 23n;
    const input = 4n; // public input

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);
    const ic1 = g1Mul(G1_GEN, ic1_s);

    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);

    // L = ic0 + input * ic1 = [ic0_s + input * ic1_s] G1
    const l_scalar = (ic0_s + input * ic1_s) % R;

    // C = [a*b - α*β - L_scalar] G1 (since gamma = delta = G2)
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - l_scalar) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0, ic1] };
    const proof: Groth16Proof = { a: A, b: B, c: C };

    expect(verifyGroth16(vk, proof, [input])).toBe(true);
  });

  it('rejects wrong public input', () => {
    const alpha_s = 3n;
    const beta_s = 5n;
    const ic0_s = 2n;
    const ic1_s = 7n;
    const a_s = 19n;
    const b_s = 23n;
    const input = 4n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);
    const ic1 = g1Mul(G1_GEN, ic1_s);

    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);

    const l_scalar = (ic0_s + input * ic1_s) % R;
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - l_scalar) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0, ic1] };
    const proof: Groth16Proof = { a: A, b: B, c: C };

    // Wrong input
    expect(verifyGroth16(vk, proof, [5n])).toBe(false);
  });

  it('throws on wrong number of inputs', () => {
    const vk: VerificationKey = {
      alpha: G1_GEN,
      beta: G2_GEN,
      gamma: G2_GEN,
      delta: G2_GEN,
      ic: [G1_GEN, G1_GEN], // expects 1 input
    };
    const proof: Groth16Proof = { a: G1_GEN, b: G2_GEN, c: G1_GEN };

    expect(() => verifyGroth16(vk, proof, [])).toThrow('expected 1 public inputs, got 0');
    expect(() => verifyGroth16(vk, proof, [1n, 2n])).toThrow('expected 1 public inputs, got 2');
  });

  it('verifies with 3 public inputs', () => {
    const alpha_s = 2n;
    const beta_s = 3n;
    const ic_scalars = [10n, 20n, 30n, 40n]; // IC[0..3]
    const a_s = 50n;
    const b_s = 60n;
    const inputs = [1n, 2n, 3n];

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic = ic_scalars.map((s) => g1Mul(G1_GEN, s));

    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);

    // L = IC[0] + input[0]*IC[1] + input[1]*IC[2] + input[2]*IC[3]
    let l_scalar = ic_scalars[0]!;
    for (let i = 0; i < inputs.length; i++) {
      l_scalar = (l_scalar + inputs[i]! * ic_scalars[i + 1]!) % R;
    }

    const c_scalar = ((a_s * b_s - alpha_s * beta_s - l_scalar) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    const vk: VerificationKey = { alpha, beta, gamma, delta, ic };
    const proof: Groth16Proof = { a: A, b: B, c: C };

    expect(verifyGroth16(vk, proof, inputs)).toBe(true);
  });
});
