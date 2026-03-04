/**
 * WOTS+ (Winternitz One-Time Signature) reference implementation.
 *
 * RFC 8391 compatible with tweakable hash function F(pubSeed, ADRS, M).
 *
 * Parameters: w=16, n=32 (SHA-256).
 *   len1 = 64  (message digits: 256 bits / 4 bits per digit)
 *   len2 = 3   (checksum digits)
 *   len  = 67  (total hash chains)
 *
 * Signature: 67 x 32 bytes = 2,144 bytes.
 * Public key: 64 bytes (pubSeed(32) || pkRoot(32)).
 *
 * Used by the Rúnar interpreter for real verification in dual-oracle tests.
 */

import { createHash, randomBytes } from 'crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const W = 16;          // Winternitz parameter (base-16)
const N = 32;          // Hash output length (SHA-256)
const LOG_W = 4;       // log2(W) = 4 bits per digit
const LEN1 = 64;       // ceil(8*N / LOG_W) = 256/4
const LEN2 = 3;        // floor(log2(LEN1 * (W-1)) / LOG_W) + 1
const LEN = LEN1 + LEN2; // 67

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * Tweakable hash function F (RFC 8391 simplified).
 * F(pubSeed, chainIdx, stepIdx, msg) = SHA-256(pubSeed || byte(chainIdx) || byte(stepIdx) || msg)
 *
 * Provides domain separation per key (pubSeed), per chain (chainIdx), and per step (stepIdx).
 */
function F(pubSeed: Uint8Array, chainIdx: number, stepIdx: number, msg: Uint8Array): Uint8Array {
  const input = new Uint8Array(N + 2 + msg.length);
  input.set(pubSeed, 0);
  input[N] = chainIdx;
  input[N + 1] = stepIdx;
  input.set(msg, N + 2);
  return sha256(input);
}

/**
 * Chain function with tweakable hashing.
 * chain(x, startStep, steps, pubSeed, chainIdx) iterates F with incrementing hash address.
 */
function chain(x: Uint8Array, startStep: number, steps: number, pubSeed: Uint8Array, chainIdx: number): Uint8Array {
  let current = x;
  for (let j = startStep; j < startStep + steps; j++) {
    current = F(pubSeed, chainIdx, j, current);
  }
  return current;
}

/** Extract base-16 digits from a 32-byte hash. Returns LEN1 = 64 digits. */
function extractDigits(hash: Uint8Array): number[] {
  const digits: number[] = [];
  for (let i = 0; i < hash.length; i++) {
    digits.push((hash[i]! >> 4) & 0x0f);  // high nibble
    digits.push(hash[i]! & 0x0f);          // low nibble
  }
  return digits;
}

/** Compute WOTS+ checksum and return LEN2 = 3 checksum digits. */
function checksumDigits(msgDigits: number[]): number[] {
  let sum = 0;
  for (const d of msgDigits) {
    sum += (W - 1) - d;
  }
  // Encode sum in base-16 as LEN2 digits (big-endian)
  const digits: number[] = [];
  let remaining = sum;
  for (let i = LEN2 - 1; i >= 0; i--) {
    digits[i] = remaining % W;
    remaining = Math.floor(remaining / W);
  }
  return digits;
}

/** Get all LEN = 67 digits: 64 message digits + 3 checksum digits. */
function allDigits(msgHash: Uint8Array): number[] {
  const msg = extractDigits(msgHash);
  const csum = checksumDigits(msg);
  return [...msg, ...csum];
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

export interface WOTSKeyPair {
  sk: Uint8Array[];   // 67 secret key elements, each 32 bytes
  pk: Uint8Array;     // 64-byte public key: pubSeed(32) || pkRoot(32)
}

/**
 * Generate a WOTS+ keypair.
 * @param seed     Optional 32-byte seed for secret key derivation. If omitted, random.
 * @param pubSeed  Optional 32-byte public seed for tweakable hashing. If omitted, random.
 */
export function wotsKeygen(seed?: Uint8Array, pubSeed?: Uint8Array): WOTSKeyPair {
  // Generate or use provided pubSeed
  const ps = pubSeed ?? new Uint8Array(randomBytes(N));

  // Generate 67 random 32-byte secret keys
  const sk: Uint8Array[] = [];
  for (let i = 0; i < LEN; i++) {
    if (seed) {
      // Deterministic: derive sk[i] = SHA-256(seed || i)
      const buf = new Uint8Array(N + 4);
      buf.set(seed);
      buf[N] = (i >> 24) & 0xff;
      buf[N + 1] = (i >> 16) & 0xff;
      buf[N + 2] = (i >> 8) & 0xff;
      buf[N + 3] = i & 0xff;
      sk.push(sha256(buf));
    } else {
      sk.push(new Uint8Array(randomBytes(N)));
    }
  }

  // Compute chain endpoints using tweakable hash
  const endpoints: Uint8Array[] = [];
  for (let i = 0; i < LEN; i++) {
    endpoints.push(chain(sk[i]!, 0, W - 1, ps, i));
  }

  // pkRoot = SHA-256(endpoint_0 || endpoint_1 || ... || endpoint_66)
  const concat = new Uint8Array(LEN * N);
  for (let i = 0; i < LEN; i++) {
    concat.set(endpoints[i]!, i * N);
  }
  const pkRoot = sha256(concat);

  // pk = pubSeed(32) || pkRoot(32) = 64 bytes
  const pk = new Uint8Array(2 * N);
  pk.set(ps, 0);
  pk.set(pkRoot, N);

  return { sk, pk };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Sign a message with WOTS+.
 * @param msg     The message to sign.
 * @param sk      Secret key elements (67 x 32 bytes).
 * @param pubSeed The 32-byte public seed (first 32 bytes of the public key).
 * @returns Signature as a single Uint8Array (67 x 32 = 2,144 bytes).
 */
export function wotsSign(msg: Uint8Array, sk: Uint8Array[], pubSeed: Uint8Array): Uint8Array {
  const msgHash = sha256(msg);
  const digits = allDigits(msgHash);

  // For each chain: hash sk[i] using tweakable chain function
  const sig = new Uint8Array(LEN * N);
  for (let i = 0; i < LEN; i++) {
    const element = chain(sk[i]!, 0, digits[i]!, pubSeed, i);
    sig.set(element, i * N);
  }
  return sig;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Verify a WOTS+ signature.
 * @param msg   The original message (NOT pre-hashed).
 * @param sig   Signature bytes (67 x 32 = 2,144 bytes).
 * @param pk    Public key (64 bytes: pubSeed(32) || pkRoot(32)).
 * @returns true if the signature is valid.
 */
export function wotsVerify(msg: Uint8Array, sig: Uint8Array, pk: Uint8Array): boolean {
  if (sig.length !== LEN * N) return false;
  if (pk.length !== 2 * N) return false;

  // Split pk into pubSeed and pkRoot
  const pubSeed = pk.slice(0, N);
  const pkRoot = pk.slice(N, 2 * N);

  const msgHash = sha256(msg);
  const digits = allDigits(msgHash);

  // For each chain: continue from sig[i] to endpoint using tweakable chain
  const endpoints: Uint8Array[] = [];
  for (let i = 0; i < LEN; i++) {
    const sigElement = sig.slice(i * N, (i + 1) * N);
    const remaining = (W - 1) - digits[i]!;
    endpoints.push(chain(sigElement, digits[i]!, remaining, pubSeed, i));
  }

  // Reconstruct pkRoot
  const concat = new Uint8Array(LEN * N);
  for (let i = 0; i < LEN; i++) {
    concat.set(endpoints[i]!, i * N);
  }
  const computedPkRoot = sha256(concat);

  // Compare
  if (computedPkRoot.length !== pkRoot.length) return false;
  for (let i = 0; i < pkRoot.length; i++) {
    if (computedPkRoot[i] !== pkRoot[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Exports for testing
// ---------------------------------------------------------------------------

export const WOTS_PARAMS = { W, N, LOG_W, LEN1, LEN2, LEN } as const;
