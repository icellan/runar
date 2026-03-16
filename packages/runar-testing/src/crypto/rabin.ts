/**
 * Real Rabin signature signing and verification for contract testing.
 *
 * Rabin verification: (sig² + padding) mod n === SHA256(msg) mod n
 * where n = p * q is the Rabin public key and (p, q) is the private key.
 *
 * The SHA256 hash is interpreted as an unsigned little-endian bigint to match
 * Bitcoin Script's OP_MOD / OP_ADD behavior.
 */

import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

export interface RabinKeyPair {
  p: bigint;
  q: bigint;
  n: bigint;
}

/**
 * Deterministic test keypair: 130-bit primes that are ≡ 3 (mod 4).
 * n must be > 2^256 so that (sig²+padding) % n has the same byte width
 * as SHA256 output — otherwise OP_EQUALVERIFY fails (byte-for-byte compare).
 */
export const RABIN_TEST_KEY: RabinKeyPair = {
  p: 1361129467683753853853498429727072846227n,
  q: 1361129467683753853853498429727082846007n,
  n: 1361129467683753853853498429727072846227n * 1361129467683753853853498429727082846007n,
};

export function generateRabinKeyPair(): RabinKeyPair {
  return { ...RABIN_TEST_KEY };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Sign a message with a Rabin private key.
 *
 * @param msg - Message bytes (Uint8Array)
 * @param kp - Rabin key pair containing p, q, n
 * @returns sig and padding as bigints
 */
export function rabinSign(
  msg: Uint8Array,
  kp: RabinKeyPair,
): { sig: bigint; padding: bigint } {
  const hash = createHash('sha256').update(msg).digest();
  const hashBN = bytesToUnsignedLE(hash);

  for (let padding = 0n; padding < 1000n; padding++) {
    let target = (hashBN - padding) % kp.n;
    if (target < 0n) target += kp.n;
    if (isQR(target, kp.p) && isQR(target, kp.q)) {
      const sp = modPow(target, (kp.p + 1n) / 4n, kp.p);
      const sq = modPow(target, (kp.q + 1n) / 4n, kp.q);
      const sig = crt(sp, kp.p, sq, kp.q);
      if ((sig * sig + padding) % kp.n === hashBN % kp.n) {
        return { sig, padding };
      }
      const sigAlt = kp.n - sig;
      if ((sigAlt * sigAlt + padding) % kp.n === hashBN % kp.n) {
        return { sig: sigAlt, padding };
      }
    }
  }
  throw new Error('Rabin sign: no valid padding found');
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Verify a Rabin signature.
 *
 * Equation: (sig² + padding) mod n === SHA256(msg) mod n
 *
 * @param msg - Message bytes (Uint8Array)
 * @param sig - Signature value (bigint)
 * @param padding - Padding bytes (Uint8Array), interpreted as unsigned LE bigint
 * @param pubkey - Public key / modulus n (bigint)
 */
export function rabinVerify(
  msg: Uint8Array,
  sig: bigint,
  padding: Uint8Array,
  pubkey: bigint,
): boolean {
  if (pubkey <= 0n) return false;
  const hash = createHash('sha256').update(msg).digest();
  const hashBN = bytesToUnsignedLE(hash);
  const padBN = bytesToUnsignedLE(padding);
  const lhs = ((sig * sig + padBN) % pubkey + pubkey) % pubkey;
  const rhs = (hashBN % pubkey + pubkey) % pubkey;
  return lhs === rhs;
}

/**
 * Verify a Rabin signature with hex-encoded msg and padding.
 * Convenience wrapper for runtime builtins (where ByteString = hex string).
 */
export function rabinVerifyHex(
  msgHex: string,
  sig: bigint,
  paddingHex: string,
  pubkey: bigint,
): boolean {
  return rabinVerify(hexToBytes(msgHex), sig, hexToBytes(paddingHex), pubkey);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function isQR(a: bigint, p: bigint): boolean {
  if (a % p === 0n) return true;
  return modPow(a, (p - 1n) / 2n, p) === 1n;
}

function crt(a1: bigint, m1: bigint, a2: bigint, m2: bigint): bigint {
  const m = m1 * m2;
  const p1 = modPow(m2, m1 - 2n, m1);
  const p2 = modPow(m1, m2 - 2n, m2);
  return ((a1 * m2 * p1 + a2 * m1 * p2) % m + m) % m;
}

function bytesToUnsignedLE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result += BigInt(bytes[i]!) << BigInt(i * 8);
  }
  return result;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}
