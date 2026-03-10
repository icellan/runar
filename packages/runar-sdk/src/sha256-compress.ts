// ---------------------------------------------------------------------------
// sha256-compress.ts — SHA-256 compression utility for inductive contracts
// ---------------------------------------------------------------------------
//
// Provides a pure SHA-256 compression function and a helper that computes
// partial SHA-256 state for inductive contract parent-tx verification.
// The on-chain script receives only the last 2 blocks and the intermediate
// hash state, avoiding the need to push the full raw parent tx.
// ---------------------------------------------------------------------------

/**
 * SHA-256 round constants (FIPS 180-4 Section 4.2.2).
 * 64 values derived from the fractional parts of the cube roots of
 * the first 64 primes.
 */
export const SHA256_K: readonly number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/**
 * SHA-256 initial hash values (FIPS 180-4 Section 5.3.3).
 * Derived from the fractional parts of the square roots of
 * the first 8 primes.
 */
export const SHA256_INIT: readonly number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/**
 * Pure SHA-256 compression function for one 64-byte block.
 *
 * Takes an 8-word intermediate hash state and a 64-byte message block,
 * applies the 64 rounds of SHA-256 compression, and returns the
 * updated 8-word state.
 *
 * @param state  - 8-element Uint32Array (current hash state, 32 bytes)
 * @param block  - 64-byte Uint8Array (one SHA-256 message block)
 * @returns New 8-element Uint32Array with the updated hash state
 */
export function sha256CompressBlock(state: Uint32Array, block: Uint8Array): Uint32Array {
  if (state.length !== 8) {
    throw new Error(`sha256CompressBlock: state must be 8 words, got ${state.length}`);
  }
  if (block.length !== 64) {
    throw new Error(`sha256CompressBlock: block must be 64 bytes, got ${block.length}`);
  }

  const rotr = (x: number, n: number): number => ((x >>> n) | (x << (32 - n))) >>> 0;
  const add32 = (a: number, b: number): number => (a + b) >>> 0;

  // Expand 16 message words to 64
  const W = new Uint32Array(64);
  for (let i = 0; i < 16; i++) {
    W[i] = ((block[i * 4]! << 24) |
            (block[i * 4 + 1]! << 16) |
            (block[i * 4 + 2]! << 8) |
             block[i * 4 + 3]!) >>> 0;
  }
  for (let t = 16; t < 64; t++) {
    const s0 = (rotr(W[t - 15]!, 7) ^ rotr(W[t - 15]!, 18) ^ (W[t - 15]! >>> 3)) >>> 0;
    const s1 = (rotr(W[t - 2]!, 17) ^ rotr(W[t - 2]!, 19) ^ (W[t - 2]! >>> 10)) >>> 0;
    W[t] = add32(add32(add32(s1, W[t - 7]!), s0), W[t - 16]!);
  }

  // Initialize working variables
  let a = state[0]!;
  let b = state[1]!;
  let c = state[2]!;
  let d = state[3]!;
  let e = state[4]!;
  let f = state[5]!;
  let g = state[6]!;
  let h = state[7]!;

  // 64 rounds of compression
  for (let t = 0; t < 64; t++) {
    const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
    const ch = ((e & f) ^ (~e & g)) >>> 0;
    const T1 = add32(add32(add32(add32(h, S1), ch), SHA256_K[t]!), W[t]!);
    const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
    const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
    const T2 = add32(S0, maj);
    h = g; g = f; f = e; e = add32(d, T1);
    d = c; c = b; b = a; a = add32(T1, T2);
  }

  // Add compressed chunk to current hash state
  return new Uint32Array([
    add32(a, state[0]!),
    add32(b, state[1]!),
    add32(c, state[2]!),
    add32(d, state[3]!),
    add32(e, state[4]!),
    add32(f, state[5]!),
    add32(g, state[6]!),
    add32(h, state[7]!),
  ]);
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

function stateToHex(state: Uint32Array): string {
  let hex = '';
  for (let i = 0; i < state.length; i++) {
    hex += state[i]!.toString(16).padStart(8, '0');
  }
  return hex;
}

// ---------------------------------------------------------------------------
// SHA-256 padding
// ---------------------------------------------------------------------------

/**
 * Apply SHA-256 padding to a message (FIPS 180-4 Section 5.1.1).
 *
 * Appends:
 *   1. A single 0x80 byte
 *   2. Zero bytes until (length mod 64) === 56
 *   3. 8-byte big-endian bit length of the original message
 *
 * @param message - Raw message bytes
 * @returns Padded message (length is a multiple of 64)
 */
function sha256Pad(message: Uint8Array): Uint8Array {
  const msgLen = message.length;
  const bitLen = msgLen * 8;

  // Calculate padded length: message + 0x80 + zeros + 8 bytes length
  // Total must be a multiple of 64 with the length fitting in the last 8 bytes
  let paddedLen = msgLen + 1; // +1 for the 0x80 byte
  while (paddedLen % 64 !== 56) {
    paddedLen++;
  }
  paddedLen += 8; // 8-byte big-endian bit length

  const padded = new Uint8Array(paddedLen);
  padded.set(message);
  padded[msgLen] = 0x80;

  // Append 8-byte big-endian bit length
  // For messages up to ~256 MB, the upper 4 bytes are always 0.
  // JavaScript numbers can handle up to 2^53 bits, which covers any
  // realistic transaction size.
  const lenOffset = paddedLen - 8;
  // Upper 32 bits of the 64-bit bit length
  const hiLen = Math.floor(bitLen / 0x100000000);
  padded[lenOffset]     = (hiLen >>> 24) & 0xff;
  padded[lenOffset + 1] = (hiLen >>> 16) & 0xff;
  padded[lenOffset + 2] = (hiLen >>> 8)  & 0xff;
  padded[lenOffset + 3] =  hiLen         & 0xff;
  // Lower 32 bits
  padded[lenOffset + 4] = (bitLen >>> 24) & 0xff;
  padded[lenOffset + 5] = (bitLen >>> 16) & 0xff;
  padded[lenOffset + 6] = (bitLen >>> 8)  & 0xff;
  padded[lenOffset + 7] =  bitLen         & 0xff;

  return padded;
}

// ---------------------------------------------------------------------------
// Partial SHA-256 for inductive contracts
// ---------------------------------------------------------------------------

export interface PartialSha256Result {
  /** 32-byte hex: intermediate SHA-256 state after compressing blocks 0..N-3 */
  parentHashState: string;
  /** 64-byte hex: the (N-1)th block (second-to-last) */
  parentTailBlock1: string;
  /** 64-byte hex: the Nth block (last, contains padding) */
  parentTailBlock2: string;
  /** Number of raw (unpadded) tx bytes in the two tail blocks */
  parentRawTailLen: number;
}

/**
 * Compute partial SHA-256 for an inductive contract's parent transaction.
 *
 * Instead of pushing the full raw parent tx on-chain, we pre-compute the
 * SHA-256 state up to (but not including) the last 2 blocks. The on-chain
 * script receives:
 *   - The intermediate hash state (32 bytes)
 *   - The two tail blocks (64 bytes each)
 *   - The raw tail length (to locate fields within the tail)
 *
 * It then completes the double-SHA256 to derive the parent txid and
 * verifies it against the outpoint in the sighash preimage.
 *
 * @param rawTxHex - Full raw transaction hex
 * @returns The 4 partial SHA-256 components needed by the on-chain script
 */
export function computePartialSha256ForInductive(rawTxHex: string): PartialSha256Result {
  const rawBytes = hexToBytes(rawTxHex);
  const padded = sha256Pad(rawBytes);
  const totalBlocks = padded.length / 64;

  if (totalBlocks < 2) {
    // Any valid Bitcoin tx is at least ~60 bytes, so after SHA-256 padding
    // we always get >= 2 blocks. But handle the degenerate case: use the
    // SHA-256 initial state and synthesize a second block of pure padding.
    // This should never happen in practice.
    const initState = stateToHex(new Uint32Array(SHA256_INIT));
    const block1 = bytesToHex(padded.subarray(0, 64));
    // Create a second block filled with zeros (degenerate padding block)
    const block2 = '00'.repeat(64);
    return {
      parentHashState: initState,
      parentTailBlock1: block1,
      parentTailBlock2: block2,
      parentRawTailLen: rawBytes.length,
    };
  }

  // Compress all blocks except the last 2 to get intermediate state
  let state: Uint32Array = new Uint32Array(SHA256_INIT);
  const preHashedBlocks = totalBlocks - 2;
  for (let i = 0; i < preHashedBlocks; i++) {
    const block = padded.slice(i * 64, (i + 1) * 64);
    state = sha256CompressBlock(state, block);
  }

  const tailBlock1 = padded.slice(preHashedBlocks * 64, (preHashedBlocks + 1) * 64);
  const tailBlock2 = padded.slice((preHashedBlocks + 1) * 64, (preHashedBlocks + 2) * 64);

  // Raw tail length = total raw bytes minus the bytes already compressed
  const rawTailLen = rawBytes.length - preHashedBlocks * 64;

  return {
    parentHashState: stateToHex(state),
    parentTailBlock1: bytesToHex(tailBlock1),
    parentTailBlock2: bytesToHex(tailBlock2),
    parentRawTailLen: rawTailLen,
  };
}
