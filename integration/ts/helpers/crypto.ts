/**
 * Crypto helpers for integration tests — WOTS, Rabin, EC scalar math.
 */

import { createHash } from 'crypto';

// ---------------------------------------------------------------------------
// WOTS+ helpers
// ---------------------------------------------------------------------------

const WOTS_W = 16;
const WOTS_N = 32;
const WOTS_LEN1 = 64;
const WOTS_LEN2 = 3;
const WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;

function wotsSha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

/**
 * WOTS+ chain function F: SHA256(pubSeed || chainIdx_byte || stepIdx_byte || msg)
 * Must match the on-chain script which uses 1-byte indices in a single 66-byte hash.
 */
function wotsChain(x: Buffer, start: number, steps: number, pubSeed: Buffer, chainIdx: number): Buffer {
  let tmp = Buffer.from(x);
  for (let i = start; i < start + steps; i++) {
    const input = Buffer.concat([pubSeed, Buffer.from([chainIdx, i]), tmp]);
    tmp = wotsSha256(input);
  }
  return tmp;
}

export interface WOTSKeyPair {
  sk: Buffer[];
  pk: Buffer; // 64 bytes: pubSeed[32] || pkRoot[32]
  pubSeed: Buffer;
}

export function wotsKeygen(seed: Buffer, pubSeed: Buffer): WOTSKeyPair {
  const sk: Buffer[] = [];
  for (let i = 0; i < WOTS_LEN; i++) {
    const buf = Buffer.alloc(WOTS_N + 4);
    seed.copy(buf);
    buf.writeUInt32BE(i, WOTS_N);
    sk.push(wotsSha256(buf));
  }

  // Public key: chain each sk[i] from 0 to W-1
  const pkParts: Buffer[] = [];
  for (let i = 0; i < WOTS_LEN; i++) {
    pkParts.push(wotsChain(sk[i], 0, WOTS_W - 1, pubSeed, i));
  }

  // Hash all pk parts together for pkRoot
  const allPK = Buffer.concat(pkParts);
  const pkRoot = wotsSha256(allPK);

  return {
    sk,
    pk: Buffer.concat([pubSeed, pkRoot]),
    pubSeed,
  };
}

function wotsExtractDigits(msgHash: Buffer): number[] {
  const digits: number[] = [];
  for (let i = 0; i < WOTS_N; i++) {
    digits.push(msgHash[i] >> 4);
    digits.push(msgHash[i] & 0x0f);
  }
  return digits;
}

function wotsChecksumDigits(msgDigits: number[]): number[] {
  let csum = 0;
  for (const d of msgDigits) {
    csum += WOTS_W - 1 - d;
  }
  const digits: number[] = [];
  for (let i = WOTS_LEN2 - 1; i >= 0; i--) {
    digits.push(csum % WOTS_W);
    csum = Math.floor(csum / WOTS_W);
  }
  return digits.reverse();
}

export function wotsSign(msg: Buffer, sk: Buffer[], pubSeed: Buffer): Buffer {
  const msgHash = wotsSha256(msg);
  const msgDigits = wotsExtractDigits(msgHash);
  const csumDigits = wotsChecksumDigits(msgDigits);
  const allDigits = [...msgDigits, ...csumDigits];

  const sigParts: Buffer[] = [];
  for (let i = 0; i < WOTS_LEN; i++) {
    sigParts.push(wotsChain(sk[i], 0, allDigits[i], pubSeed, i));
  }
  return Buffer.concat(sigParts);
}

export function wotsPubKeyHex(kp: WOTSKeyPair): string {
  return kp.pk.toString('hex');
}

// ---------------------------------------------------------------------------
// Rabin helpers
// ---------------------------------------------------------------------------

export interface RabinKeyPair {
  p: bigint;
  q: bigint;
  n: bigint;
}

function isQR(a: bigint, p: bigint): boolean {
  if (a % p === 0n) return true;
  const exp = (p - 1n) / 2n;
  return modPow(a, exp, p) === 1n;
}

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

function crt(a1: bigint, m1: bigint, a2: bigint, m2: bigint): bigint {
  const m = m1 * m2;
  const p1 = modPow(m2, m1 - 2n, m1);
  const p2 = modPow(m1, m2 - 2n, m2);
  return ((a1 * m2 * p1 + a2 * m1 * p2) % m + m) % m;
}

export function generateRabinKeyPair(): RabinKeyPair {
  // Deterministic test keypair: 130-bit primes that are ≡ 3 (mod 4).
  // n must be > 2^256 so that (sig²+padding) % n has the same byte width
  // as SHA256 output — otherwise OP_EQUALVERIFY fails (byte-for-byte compare).
  const p = 1361129467683753853853498429727072846227n; // 130-bit prime, ≡ 3 mod 4
  const q = 1361129467683753853853498429727082846007n; // 130-bit prime, ≡ 3 mod 4
  return { p, q, n: p * q };
}

export function rabinSign(msg: Buffer, kp: RabinKeyPair): { sig: bigint; padding: bigint } {
  const hash = createHash('sha256').update(msg).digest();
  // Interpret hash as unsigned little-endian (matches Bitcoin Script OP_MOD/OP_ADD)
  let hashBN = bufferToUnsignedLE(hash);

  // On-chain equation: (sig² + padding) mod n === hash mod n
  // So: sig = sqrt(hash - padding)
  for (let padding = 0n; padding < 1000n; padding++) {
    let target = (hashBN - padding) % kp.n;
    if (target < 0n) target += kp.n;
    if (isQR(target, kp.p) && isQR(target, kp.q)) {
      const sp = modPow(target, (kp.p + 1n) / 4n, kp.p);
      const sq = modPow(target, (kp.q + 1n) / 4n, kp.q);
      const sig = crt(sp, kp.p, sq, kp.q);
      // Verify: sig² + padding ≡ hash (mod n)
      if ((sig * sig + padding) % kp.n === hashBN % kp.n) {
        return { sig, padding };
      }
      // Try negative root
      const sigAlt = kp.n - sig;
      if ((sigAlt * sigAlt + padding) % kp.n === hashBN % kp.n) {
        return { sig: sigAlt, padding };
      }
    }
  }
  throw new Error('Rabin sign: no valid padding found');
}

function bufferToUnsignedLE(buf: Buffer): bigint {
  let result = 0n;
  for (let i = 0; i < buf.length; i++) {
    result += BigInt(buf[i]!) << BigInt(i * 8);
  }
  return result;
}

// ---------------------------------------------------------------------------
// EC scalar helpers (secp256k1)
// ---------------------------------------------------------------------------

export const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
export const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
export const EC_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
export const EC_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function modInverse(a: bigint, m: bigint): bigint {
  return modPow(((a % m) + m) % m, m - 2n, m);
}

export function ecDouble(px: bigint, py: bigint): [bigint, bigint] {
  const s = (3n * px * px * modInverse(2n * py, EC_P)) % EC_P;
  const rx = ((s * s - 2n * px) % EC_P + EC_P) % EC_P;
  const ry = ((s * (px - rx) - py) % EC_P + EC_P) % EC_P;
  return [rx, ry];
}

export function ecAdd(p1x: bigint, p1y: bigint, p2x: bigint, p2y: bigint): [bigint, bigint] {
  if (p1x === p2x && p1y === p2y) return ecDouble(p1x, p1y);
  const s = ((p2y - p1y) * modInverse(p2x - p1x, EC_P) % EC_P + EC_P) % EC_P;
  const rx = ((s * s - p1x - p2x) % EC_P + EC_P) % EC_P;
  const ry = ((s * (p1x - rx) - p1y) % EC_P + EC_P) % EC_P;
  return [rx, ry];
}

export function ecMul(px: bigint, py: bigint, k: bigint): [bigint, bigint] {
  k = ((k % EC_N) + EC_N) % EC_N;
  let rx = 0n;
  let ry = 0n;
  let qx = px;
  let qy = py;
  let first = true;
  while (k > 0n) {
    if (k & 1n) {
      if (first) {
        rx = qx;
        ry = qy;
        first = false;
      } else {
        [rx, ry] = ecAdd(rx, ry, qx, qy);
      }
    }
    [qx, qy] = ecDouble(qx, qy);
    k >>= 1n;
  }
  return [rx, ry];
}

export function ecMulGen(k: bigint): [bigint, bigint] {
  return ecMul(EC_GX, EC_GY, k);
}

export function encodePoint(x: bigint, y: bigint): string {
  return x.toString(16).padStart(64, '0') + y.toString(16).padStart(64, '0');
}
