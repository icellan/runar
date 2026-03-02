/**
 * WOTS+ (Winternitz One-Time Signature) reference implementation.
 *
 * Parameters: w=16, n=32 (SHA-256).
 *   len1 = 64  (message digits: 256 bits / 4 bits per digit)
 *   len2 = 3   (checksum digits)
 *   len  = 67  (total hash chains)
 *
 * Signature: 67 x 32 bytes = 2,144 bytes.
 * Public key: 32 bytes (SHA-256 of concatenated chain endpoints).
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

/** Hash a value `steps` times: H(H(H(...H(x)...))) */
function chain(x: Uint8Array, steps: number): Uint8Array {
  let current = x;
  for (let i = 0; i < steps; i++) {
    current = sha256(current);
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
  pk: Uint8Array;     // 32-byte public key (hash of chain endpoints)
}

/**
 * Generate a WOTS+ keypair.
 * @param seed  Optional 32-byte seed. If omitted, random.
 */
export function wotsKeygen(seed?: Uint8Array): WOTSKeyPair {
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

  // Compute chain endpoints: hash each sk element W-1 = 15 times
  const endpoints: Uint8Array[] = [];
  for (let i = 0; i < LEN; i++) {
    endpoints.push(chain(sk[i]!, W - 1));
  }

  // Public key = SHA-256(endpoint_0 || endpoint_1 || ... || endpoint_66)
  const concat = new Uint8Array(LEN * N);
  for (let i = 0; i < LEN; i++) {
    concat.set(endpoints[i]!, i * N);
  }
  const pk = sha256(concat);

  return { sk, pk };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Sign a message with WOTS+.
 * @returns Signature as a single Uint8Array (67 x 32 = 2,144 bytes).
 */
export function wotsSign(msg: Uint8Array, sk: Uint8Array[]): Uint8Array {
  const msgHash = sha256(msg);
  const digits = allDigits(msgHash);

  // For each chain: hash sk[i] exactly digit[i] times
  const sig = new Uint8Array(LEN * N);
  for (let i = 0; i < LEN; i++) {
    const element = chain(sk[i]!, digits[i]!);
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
 * @param pk    Public key (32 bytes).
 * @returns true if the signature is valid.
 */
export function wotsVerify(msg: Uint8Array, sig: Uint8Array, pk: Uint8Array): boolean {
  if (sig.length !== LEN * N) return false;
  if (pk.length !== N) return false;

  const msgHash = sha256(msg);
  const digits = allDigits(msgHash);

  // For each chain: hash sig[i] exactly (W-1 - digit[i]) more times
  const endpoints: Uint8Array[] = [];
  for (let i = 0; i < LEN; i++) {
    const sigElement = sig.slice(i * N, (i + 1) * N);
    const remaining = (W - 1) - digits[i]!;
    endpoints.push(chain(sigElement, remaining));
  }

  // Reconstruct public key
  const concat = new Uint8Array(LEN * N);
  for (let i = 0; i < LEN; i++) {
    concat.set(endpoints[i]!, i * N);
  }
  const computedPk = sha256(concat);

  // Compare
  if (computedPk.length !== pk.length) return false;
  for (let i = 0; i < pk.length; i++) {
    if (computedPk[i] !== pk[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Exports for testing
// ---------------------------------------------------------------------------

export const WOTS_PARAMS = { W, N, LOG_W, LEN1, LEN2, LEN } as const;
