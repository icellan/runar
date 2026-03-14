/**
 * Groth16 proof serialization for on-chain state storage.
 *
 * Proof format: 8 × 32-byte little-endian unsigned field elements.
 * Order: B.x.c0 | B.x.c1 | B.y.c0 | B.y.c1 | A.x | A.y | C.x | C.y
 *
 * This order matches the runtime Groth16 verifier's expected stack layout
 * (bottom-to-top after OP_SPLIT deserialization).
 *
 * All BN254 field elements are < P (254 bits), so they fit in 32 bytes LE
 * without needing a sign byte (byte 31's MSB is always 0).
 */

import type { Groth16Proof, G1Point, G2Point, Fp } from './types.js';
import { P } from './bn254/constants.js';

/** Total serialized proof size in bytes. */
export const SERIALIZED_PROOF_SIZE = 256;

/**
 * Serialize a Groth16 proof to a hex string for on-chain state storage.
 *
 * Returns a 512-character hex string (256 bytes).
 */
export function serializeGroth16Proof(proof: Groth16Proof): string {
  const parts: string[] = [
    fpToLE32Hex(proof.b.x.c0),
    fpToLE32Hex(proof.b.x.c1),
    fpToLE32Hex(proof.b.y.c0),
    fpToLE32Hex(proof.b.y.c1),
    fpToLE32Hex(proof.a.x),
    fpToLE32Hex(proof.a.y),
    fpToLE32Hex(proof.c.x),
    fpToLE32Hex(proof.c.y),
  ];
  return parts.join('');
}

/**
 * Deserialize a hex string back to a Groth16 proof.
 */
export function deserializeGroth16Proof(hex: string): Groth16Proof {
  if (hex.length !== SERIALIZED_PROOF_SIZE * 2) {
    throw new Error(
      `Expected ${SERIALIZED_PROOF_SIZE * 2} hex chars, got ${hex.length}`,
    );
  }

  const fields: bigint[] = [];
  for (let i = 0; i < 8; i++) {
    fields.push(le32HexToFp(hex.slice(i * 64, (i + 1) * 64)));
  }

  const b: G2Point = {
    x: { c0: fields[0]!, c1: fields[1]! },
    y: { c0: fields[2]!, c1: fields[3]! },
  };
  const a: G1Point = { x: fields[4]!, y: fields[5]! };
  const c: G1Point = { x: fields[6]!, y: fields[7]! };

  return { a, b, c };
}

/** Convert a field element to 32-byte little-endian hex. */
function fpToLE32Hex(n: Fp): string {
  let v = ((n % P) + P) % P;
  const bytes: number[] = [];
  for (let i = 0; i < 32; i++) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Convert 32-byte little-endian hex to a field element. */
function le32HexToFp(hex: string): Fp {
  let result = 0n;
  for (let i = 31; i >= 0; i--) {
    result = (result << 8n) | BigInt(parseInt(hex.slice(i * 2, i * 2 + 2), 16));
  }
  return result;
}
