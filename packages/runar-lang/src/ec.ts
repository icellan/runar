// ---------------------------------------------------------------------------
// runar-lang/ec.ts — secp256k1 elliptic curve constants
// ---------------------------------------------------------------------------

import type { Point } from './types.js';

/** secp256k1 field prime: 2^256 - 2^32 - 977 */
export const EC_P: bigint =
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;

/** secp256k1 group order */
export const EC_N: bigint =
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/** secp256k1 generator point (64 bytes: x[32] || y[32], big-endian) */
export const EC_G: Point =
  '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8' as unknown as Point;
