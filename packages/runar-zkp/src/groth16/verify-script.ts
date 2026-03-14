/**
 * Groth16 verifier → Bitcoin Script codegen.
 *
 * Generates a sequence of StackOp[] that verify a Groth16 proof on-chain.
 * The verification key is embedded as constants in the script.
 *
 * ## Architecture
 *
 * The verifier checks: e(A,B) · e(-α,β) · e(-L,γ) · e(-C,δ) = 1
 * where L = IC[0] + Σ input_i · IC[i+1].
 *
 * This is implemented as:
 * 1. IC computation (multi-scalar multiplication on G1)
 * 2. Multi-Miller loop (4 pairings computed simultaneously)
 * 3. Final exponentiation
 * 4. Check result == 1 in Fp12
 */

import type { StackOp } from 'runar-ir-schema';
import type { VerificationKey, Groth16Proof, VerifierScript } from '../types.js';
import { estimateOptimizedVerifierSize } from '../bn254/field-script.js';
import { generateGroth16VerifierForKnownProof, generateRuntimeGroth16Verifier } from '../bn254/pairing-script.js';

/**
 * Estimate the script size for a full Groth16 verifier.
 */
export function estimateVerifierSize(vk: VerificationKey): {
  totalBytes: number;
  totalKB: number;
  breakdown: Record<string, number>;
  feasible: boolean;
} {
  const numInputs = vk.ic.length - 1;
  const est = estimateOptimizedVerifierSize(numInputs);

  return {
    ...est,
    feasible: true, // Always feasible on BSV
  };
}

/**
 * Generate a Groth16 verifier script for a known proof and public inputs.
 *
 * All values (VK, proof, inputs) are baked in as constants. This produces
 * a self-contained script that verifies the specific proof.
 *
 * Returns StackOp[] that, when executed, leave OP_TRUE on the stack
 * if the proof is valid, or cause the script to fail otherwise.
 */
export function generateVerifier(
  vk: VerificationKey,
  proof: Groth16Proof,
  publicInputs: bigint[],
): VerifierScript {
  const { ops, sizeBytes } = generateGroth16VerifierForKnownProof(vk, proof, publicInputs);
  return {
    ops,
    scriptSizeBytes: sizeBytes,
    opcodeCount: ops.length,
  };
}

/**
 * Generate a runtime Groth16 verifier script.
 *
 * The VK is embedded as constants. Proof points A (G1), B (G2), C (G1)
 * are runtime values pushed in the unlock script.
 *
 * Stack input (unlock script, bottom to top):
 *   [B.x.c0, B.x.c1, B.y.c0, B.y.c1, A.x, A.y, C.x, C.y, input_0, ..., input_{n-1}]
 *
 * Returns StackOp[] that leave 1 on the stack if the proof is valid, 0 otherwise.
 */
export function generateRuntimeVerifier(
  vk: VerificationKey,
  numPublicInputs: number,
): VerifierScript {
  const { ops, sizeBytes } = generateRuntimeGroth16Verifier(vk, numPublicInputs);
  return {
    ops,
    scriptSizeBytes: sizeBytes,
    opcodeCount: ops.length,
  };
}

/**
 * Generate a STUB Groth16 verifier script.
 *
 * This version drops all proof/input data and pushes OP_TRUE.
 * Used for testing when the real verifier is not needed.
 */
export function generateVerifierStub(
  _vk: VerificationKey,
  numPublicInputs: number,
): VerifierScript {
  const ops: StackOp[] = [];

  // Drop proof components (8 field elements)
  for (let i = 0; i < 8; i++) {
    ops.push({ op: 'drop' } as StackOp);
  }

  // Drop public inputs
  for (let i = 0; i < numPublicInputs; i++) {
    ops.push({ op: 'drop' } as StackOp);
  }

  // Push OP_TRUE
  ops.push({ op: 'opcode', code: 'OP_TRUE' } as StackOp);

  return {
    ops,
    scriptSizeBytes: ops.length,
    opcodeCount: ops.length,
  };
}
