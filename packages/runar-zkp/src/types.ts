/**
 * Core ZKP types for Groth16 on BN254.
 *
 * All field elements and curve points use bigint for precision.
 * Byte representations are big-endian 32-byte arrays.
 */

// ---------------------------------------------------------------------------
// Field elements
// ---------------------------------------------------------------------------

/** Element of the BN254 base field Fp (256-bit prime). */
export type Fp = bigint;

/** Element of the quadratic extension Fp2 = Fp[u] / (u^2 + 1). */
export interface Fp2 {
  readonly c0: Fp; // real part
  readonly c1: Fp; // imaginary part (coefficient of u)
}

/** Element of Fp6 = Fp2[v] / (v^3 - ξ) where ξ = 9 + u. */
export interface Fp6 {
  readonly c0: Fp2;
  readonly c1: Fp2;
  readonly c2: Fp2;
}

/** Element of Fp12 = Fp6[w] / (w^2 - v). */
export interface Fp12 {
  readonly c0: Fp6;
  readonly c1: Fp6;
}

// ---------------------------------------------------------------------------
// Curve points
// ---------------------------------------------------------------------------

/** Point on BN254 G1 (over Fp). Infinity represented as { x: 0n, y: 0n, infinity: true }. */
export interface G1Point {
  readonly x: Fp;
  readonly y: Fp;
  readonly infinity?: boolean;
}

/** Point on BN254 G2 (over Fp2). */
export interface G2Point {
  readonly x: Fp2;
  readonly y: Fp2;
  readonly infinity?: boolean;
}

// ---------------------------------------------------------------------------
// Groth16 proof and keys
// ---------------------------------------------------------------------------

/** Groth16 proof: three curve points (A ∈ G1, B ∈ G2, C ∈ G1). */
export interface Groth16Proof {
  readonly a: G1Point;   // π_A ∈ G1
  readonly b: G2Point;   // π_B ∈ G2
  readonly c: G1Point;   // π_C ∈ G1
}

/** Groth16 verification key. */
export interface VerificationKey {
  readonly alpha: G1Point;      // α ∈ G1
  readonly beta: G2Point;       // β ∈ G2
  readonly gamma: G2Point;      // γ ∈ G2
  readonly delta: G2Point;      // δ ∈ G2
  readonly ic: G1Point[];       // IC[0..l] ∈ G1 (one per public input + 1)
}

/** Groth16 proving key (for off-chain proving). */
export interface ProvingKey {
  readonly vk: VerificationKey;
  // Additional proving-specific data would go here
  // (toxic waste polynomials, etc.)
}

// ---------------------------------------------------------------------------
// Serialized forms (for on-chain use)
// ---------------------------------------------------------------------------

/** Serialized Groth16 proof as raw bytes (for embedding in Bitcoin Script). */
export interface SerializedProof {
  /** A point: 64 bytes (x[32] || y[32], uncompressed) */
  readonly a: Uint8Array;
  /** B point: 128 bytes (x.c0[32] || x.c1[32] || y.c0[32] || y.c1[32]) */
  readonly b: Uint8Array;
  /** C point: 64 bytes (x[32] || y[32], uncompressed) */
  readonly c: Uint8Array;
}

/** Total proof size: A(64) + B(128) + C(64) = 256 bytes, stored as 8 × 32-byte LE field elements. */
export const PROOF_BYTE_SIZE = 256;

// ---------------------------------------------------------------------------
// Script codegen output
// ---------------------------------------------------------------------------

/** Result of generating a Groth16 verifier as Bitcoin Script. */
export interface VerifierScript {
  /** The StackOp[] that implement the verifier. */
  readonly ops: unknown[]; // StackOp[] from runar-ir-schema
  /** Estimated script size in bytes. */
  readonly scriptSizeBytes: number;
  /** Number of opcodes. */
  readonly opcodeCount: number;
}
