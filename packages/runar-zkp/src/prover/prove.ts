/**
 * Groth16 prover — mock implementation.
 *
 * Generates synthetic Groth16 proofs that actually pass verification.
 * Uses the algebraic structure of the pairing equation to compute
 * valid proofs without a real R1CS constraint system.
 *
 * The verification equation is:
 *   e(A, B) = e(alpha, beta) · e(L, gamma) · e(C, delta)
 *
 * For gamma = delta = G2 (which our mock setup uses):
 *   C = [a*b - α*β - L_scalar] G1
 *
 * NOT SECURE — these proofs are trivially forgeable.
 * A real prover would use R1CS witness assignment + polynomial evaluation.
 */

import type { Groth16Proof, ProvingKey, Fp, G1Point, G2Point, VerificationKey } from '../types.js';
import { G1_X, G1_Y, G2_X_C0, G2_X_C1, G2_Y_C0, G2_Y_C1, R } from '../bn254/constants.js';
import { g1Mul } from '../bn254/g1.js';
import { g2Mul } from '../bn254/g2.js';

const G1_GEN: G1Point = { x: G1_X, y: G1_Y };
const G2_GEN: G2Point = {
  x: { c0: G2_X_C0, c1: G2_X_C1 },
  y: { c0: G2_Y_C0, c1: G2_Y_C1 },
};

/**
 * Generate a mock Groth16 proof that passes off-chain verification.
 *
 * Uses random-looking scalar multiples of generators and computes C
 * algebraically so the pairing equation holds.
 *
 * @param pk - Proving key (contains the verification key)
 * @param publicInputs - Public inputs to the circuit
 * @param _witness - Ignored (mock prover doesn't use witness)
 * @returns A valid Groth16 proof
 */
export function mockProve(
  pk: ProvingKey,
  publicInputs: Fp[],
  _witness?: unknown,
): Groth16Proof {
  return mockProveWithVK(pk.vk, publicInputs);
}

/**
 * Generate a mock Groth16 proof directly from a verification key.
 * Convenience function that doesn't require a full ProvingKey.
 */
export function mockProveWithVK(
  vk: VerificationKey,
  publicInputs: Fp[],
): Groth16Proof {
  if (publicInputs.length + 1 !== vk.ic.length) {
    throw new Error(
      `Expected ${vk.ic.length - 1} public inputs but got ${publicInputs.length}`,
    );
  }

  // Use deterministic "random" scalars based on a simple hash of inputs
  // This ensures reproducibility in tests
  let seed = 42n;
  for (const inp of publicInputs) {
    seed = (seed * 31n + inp) % R;
  }
  const a_s = seed === 0n ? 13n : seed;
  const b_s = ((a_s * 7n + 3n) % R) || 17n;

  // Compute the VK scalars. For our mock setup, alpha = [alpha_s]G1 etc.
  // Since mockSetup uses G1_GEN and G2_GEN as all points, the scalars
  // are effectively 1 for all IC points and VK points.
  //
  // For the general mock case, we need the algebraic relationship.
  // With gamma = G2 = [1]G2 and delta = G2 = [1]G2:
  //   e(A, B) = e(alpha, beta) · e(L, gamma) · e(C, delta)
  //   e([a]G1, [b]G2) = e(alpha, beta) · e(L, [1]G2) · e(C, [1]G2)
  //
  // This holds iff: a*b = alpha_s*beta_s + L_scalar + c_s  (in the exponent)
  // So: c_s = a*b - alpha_s*beta_s - L_scalar
  //
  // For the mock setup where all VK points are G1_GEN (scalar 1):
  //   alpha_s = 1, beta_s = 1, ic_i_scalar = 1
  //   L_scalar = 1 + sum(inputs[i] * 1) = 1 + sum(inputs)
  //   c_s = a_s * b_s - 1 - (1 + sum(inputs))

  // Compute L scalar assuming IC[i] = [1]G1 (mock setup)
  let l_scalar = 1n; // IC[0] scalar
  for (const inp of publicInputs) {
    l_scalar = (l_scalar + inp) % R;
  }

  const alpha_s = 1n; // mock setup uses G1_GEN
  const beta_s = 1n;  // mock setup uses G2_GEN
  const c_scalar = ((a_s * b_s - alpha_s * beta_s - l_scalar) % R + R) % R;

  const A = g1Mul(G1_GEN, a_s);
  const B = g2Mul(G2_GEN, b_s);
  const C = g1Mul(G1_GEN, c_scalar);

  return { a: A, b: B, c: C };
}
