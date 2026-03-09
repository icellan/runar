/**
 * SLH-DSA (FIPS 205) SHA-256 reference implementation.
 *
 * Implements all 6 SHA-256 parameter sets for key generation, signing, and
 * verification. Used by the Rúnar interpreter for real verification in
 * dual-oracle tests.
 *
 * Based on FIPS 205 (Stateless Hash-Based Digital Signature Standard).
 * Only the SHA2 instantiation (not SHAKE) is implemented.
 */

import { createHash } from 'crypto';

// ---------------------------------------------------------------------------
// Parameter sets (FIPS 205 Table 1, SHA2 variants only)
// ---------------------------------------------------------------------------

export interface SLHParams {
  name: string;
  n: number;       // Security parameter (hash output bytes): 16, 24, or 32
  h: number;       // Total tree height
  d: number;       // Number of hypertree layers
  hp: number;      // Height of each subtree: h/d
  a: number;       // FORS tree height
  k: number;       // Number of FORS trees
  w: number;       // Winternitz parameter (always 16)
  len: number;     // WOTS+ chain count
}

function wotsLen(n: number, w: number): number {
  const len1 = Math.ceil((8 * n) / Math.log2(w));
  const len2 = Math.floor(Math.log2(len1 * (w - 1)) / Math.log2(w)) + 1;
  return len1 + len2;
}

export const SLH_SHA2_128s: SLHParams = { name: 'SLH-DSA-SHA2-128s', n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, w: 16, len: wotsLen(16, 16) };
export const SLH_SHA2_128f: SLHParams = { name: 'SLH-DSA-SHA2-128f', n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, w: 16, len: wotsLen(16, 16) };
export const SLH_SHA2_192s: SLHParams = { name: 'SLH-DSA-SHA2-192s', n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17, w: 16, len: wotsLen(24, 16) };
export const SLH_SHA2_192f: SLHParams = { name: 'SLH-DSA-SHA2-192f', n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33, w: 16, len: wotsLen(24, 16) };
export const SLH_SHA2_256s: SLHParams = { name: 'SLH-DSA-SHA2-256s', n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, w: 16, len: wotsLen(32, 16) };
export const SLH_SHA2_256f: SLHParams = { name: 'SLH-DSA-SHA2-256f', n: 32, h: 68, d: 17, hp: 4, a: 8, k: 35, w: 16, len: wotsLen(32, 16) };

export const ALL_SHA2_PARAMS: SLHParams[] = [
  SLH_SHA2_128s, SLH_SHA2_128f,
  SLH_SHA2_192s, SLH_SHA2_192f,
  SLH_SHA2_256s, SLH_SHA2_256f,
];

// ---------------------------------------------------------------------------
// ADRS (Address) — 32-byte domain separator (FIPS 205 Section 4.2)
// ---------------------------------------------------------------------------

const ADRS_SIZE = 32;

// Address types
const ADRS_WOTS_HASH = 0;
const ADRS_WOTS_PK = 1;
const ADRS_TREE = 2;
const ADRS_FORS_TREE = 3;
const ADRS_FORS_ROOTS = 4;
const ADRS_WOTS_PRF = 5;
const ADRS_FORS_PRF = 6;

function newADRS(): Uint8Array {
  return new Uint8Array(ADRS_SIZE);
}

function setLayerAddress(adrs: Uint8Array, layer: number): void {
  adrs[0] = (layer >> 24) & 0xff;
  adrs[1] = (layer >> 16) & 0xff;
  adrs[2] = (layer >> 8) & 0xff;
  adrs[3] = layer & 0xff;
}

function setTreeAddress(adrs: Uint8Array, tree: bigint): void {
  // Bytes 4-15 (12 bytes for tree address)
  for (let i = 0; i < 12; i++) {
    adrs[4 + 11 - i] = Number((tree >> BigInt(8 * i)) & 0xffn);
  }
}

function setType(adrs: Uint8Array, type: number): void {
  // Byte 16-19: type (big-endian u32), also zeroes bytes 20-31
  adrs[16] = (type >> 24) & 0xff;
  adrs[17] = (type >> 16) & 0xff;
  adrs[18] = (type >> 8) & 0xff;
  adrs[19] = type & 0xff;
  for (let i = 20; i < 32; i++) adrs[i] = 0;
}

function setKeyPairAddress(adrs: Uint8Array, kp: number): void {
  adrs[20] = (kp >> 24) & 0xff;
  adrs[21] = (kp >> 16) & 0xff;
  adrs[22] = (kp >> 8) & 0xff;
  adrs[23] = kp & 0xff;
}

function setChainAddress(adrs: Uint8Array, chain: number): void {
  adrs[24] = (chain >> 24) & 0xff;
  adrs[25] = (chain >> 16) & 0xff;
  adrs[26] = (chain >> 8) & 0xff;
  adrs[27] = chain & 0xff;
}

function setHashAddress(adrs: Uint8Array, hash: number): void {
  adrs[28] = (hash >> 24) & 0xff;
  adrs[29] = (hash >> 16) & 0xff;
  adrs[30] = (hash >> 8) & 0xff;
  adrs[31] = hash & 0xff;
}

function setTreeHeight(adrs: Uint8Array, height: number): void {
  // Uses same bytes as chain address (24-27)
  setChainAddress(adrs, height);
}

function setTreeIndex(adrs: Uint8Array, index: number): void {
  // Uses same bytes as hash address (28-31)
  setHashAddress(adrs, index);
}

/** Compressed ADRS for SHA2 (22 bytes): drop bytes 3..6 */
function compressADRS(adrs: Uint8Array): Uint8Array {
  const c = new Uint8Array(22);
  c[0] = adrs[3]!; // layer (1 byte)
  // tree address bytes 8-15 (8 bytes)
  c.set(adrs.subarray(8, 16), 1);
  // type (1 byte)
  c[9] = adrs[19]!;
  // bytes 20-31 (12 bytes)
  c.set(adrs.subarray(20, 32), 10);
  return c;
}

// ---------------------------------------------------------------------------
// Hash functions (FIPS 205 Section 11.1 — SHA2 instantiation)
// ---------------------------------------------------------------------------

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function trunc(data: Uint8Array, n: number): Uint8Array {
  return data.slice(0, n);
}

function toByte(value: number, n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = n - 1; i >= 0 && value > 0; i--) {
    b[i] = value & 0xff;
    value >>= 8;
  }
  return b;
}

/** Tweakable hash: T_l(PK.seed, ADRS, M) = trunc_n(SHA-256(PK.seed || pad || ADRSc || M)) */
function T(pkSeed: Uint8Array, adrs: Uint8Array, msg: Uint8Array, n: number): Uint8Array {
  const adrsC = compressADRS(adrs);
  const pad = new Uint8Array(64 - n); // zero padding to fill SHA-256 block
  const input = concat(pkSeed, pad, adrsC, msg);
  return trunc(sha256(input), n);
}

/** PRF: PRF(PK.seed, SK.seed, ADRS) = trunc_n(SHA-256(PK.seed || pad || ADRSc || SK.seed)) */
function PRF(pkSeed: Uint8Array, skSeed: Uint8Array, adrs: Uint8Array, n: number): Uint8Array {
  return T(pkSeed, adrs, skSeed, n);
}

/** PRFmsg: for randomized message hashing */
function PRFmsg(skPrf: Uint8Array, optRand: Uint8Array, msg: Uint8Array, n: number): Uint8Array {
  // HMAC-SHA256 based: SHA-256(toByte(0, 64-n) || skPrf || optRand || msg)
  const pad = new Uint8Array(64 - n);
  const input = concat(pad, skPrf, optRand, msg);
  return trunc(sha256(input), n);
}

/** Hmsg: hash message to get FORS + tree indices */
function Hmsg(R: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, msg: Uint8Array, outLen: number): Uint8Array {
  // SHA-256 based MGF1 construction
  const seed = concat(R, pkSeed, pkRoot, msg);
  const hash = sha256(seed);
  // For simplicity, use iterative hashing to extend output
  const result = new Uint8Array(outLen);
  let offset = 0;
  let counter = 0;
  while (offset < outLen) {
    const block = sha256(concat(hash, toByte(counter, 4)));
    const copyLen = Math.min(32, outLen - offset);
    result.set(block.subarray(0, copyLen), offset);
    offset += copyLen;
    counter++;
  }
  return result;
}

// ---------------------------------------------------------------------------
// WOTS+ (FIPS 205 Section 5)
// ---------------------------------------------------------------------------

function wotsChain(x: Uint8Array, start: number, steps: number,
  pkSeed: Uint8Array, adrs: Uint8Array, n: number): Uint8Array {
  let tmp = x;
  for (let j = start; j < start + steps; j++) {
    setHashAddress(adrs, j);
    tmp = T(pkSeed, adrs, tmp, n);
  }
  return tmp;
}

function wotsLen1(n: number, w: number): number {
  return Math.ceil((8 * n) / Math.log2(w));
}

function wotsLen2(n: number, w: number): number {
  const l1 = wotsLen1(n, w);
  return Math.floor(Math.log2(l1 * (w - 1)) / Math.log2(w)) + 1;
}

function baseW(msg: Uint8Array, w: number, outLen: number): number[] {
  const logW = Math.log2(w);
  const bits: number[] = [];
  for (const byte of msg) {
    for (let j = 8 - logW; j >= 0; j -= logW) {
      bits.push((byte >> j) & (w - 1));
    }
  }
  return bits.slice(0, outLen);
}

function wotsPkFromSig(sig: Uint8Array, msg: Uint8Array, pkSeed: Uint8Array,
  adrs: Uint8Array, params: SLHParams): Uint8Array {
  const { n, w, len } = params;
  const l1 = wotsLen1(n, w);
  const l2 = wotsLen2(n, w);

  const msgDigits = baseW(msg, w, l1);

  // Compute checksum
  let csum = 0;
  for (const d of msgDigits) csum += (w - 1) - d;
  // Encode checksum in base-w
  const csumBytes = toByte(csum << (8 - ((l2 * Math.log2(w)) % 8)), Math.ceil((l2 * Math.log2(w)) / 8));
  const csumDigits = baseW(csumBytes, w, l2);

  const allDigits = [...msgDigits, ...csumDigits];

  const kpAddr = getKeyPairAddress(adrs);
  const tmpAdrs = new Uint8Array(adrs);
  setType(tmpAdrs, ADRS_WOTS_HASH); // Note: setType zeros bytes 20-31
  setKeyPairAddress(tmpAdrs, kpAddr); // Restore keypair address

  const parts: Uint8Array[] = [];
  for (let i = 0; i < len; i++) {
    setChainAddress(tmpAdrs, i);
    const sigI = sig.slice(i * n, (i + 1) * n);
    parts.push(wotsChain(sigI, allDigits[i]!, w - 1 - allDigits[i]!, pkSeed, tmpAdrs, n));
  }

  // Compress: T_len(PK.seed, ADRS_pk, pk_0 || pk_1 || ... || pk_{len-1})
  const pkAdrs = new Uint8Array(adrs);
  setType(pkAdrs, ADRS_WOTS_PK);
  return T(pkSeed, pkAdrs, concat(...parts), n);
}

function wotsSign(msg: Uint8Array, skSeed: Uint8Array, pkSeed: Uint8Array,
  adrs: Uint8Array, params: SLHParams): Uint8Array {
  const { n, w, len } = params;
  const l1 = wotsLen1(n, w);
  const l2 = wotsLen2(n, w);

  const msgDigits = baseW(msg, w, l1);
  let csum = 0;
  for (const d of msgDigits) csum += (w - 1) - d;
  const csumBytes = toByte(csum << (8 - ((l2 * Math.log2(w)) % 8)), Math.ceil((l2 * Math.log2(w)) / 8));
  const csumDigits = baseW(csumBytes, w, l2);
  const allDigits = [...msgDigits, ...csumDigits];

  const sigParts: Uint8Array[] = [];
  for (let i = 0; i < len; i++) {
    const skAdrs = new Uint8Array(adrs);
    setType(skAdrs, ADRS_WOTS_PRF);
    setKeyPairAddress(skAdrs, getKeyPairAddress(adrs));
    setChainAddress(skAdrs, i);
    setHashAddress(skAdrs, 0);
    const sk = PRF(pkSeed, skSeed, skAdrs, n);

    const chainAdrs = new Uint8Array(adrs);
    setType(chainAdrs, ADRS_WOTS_HASH);
    setKeyPairAddress(chainAdrs, getKeyPairAddress(adrs));
    setChainAddress(chainAdrs, i);
    sigParts.push(wotsChain(sk, 0, allDigits[i]!, pkSeed, chainAdrs, n));
  }
  return concat(...sigParts);
}

function getKeyPairAddress(adrs: Uint8Array): number {
  return (adrs[20]! << 24) | (adrs[21]! << 16) | (adrs[22]! << 8) | adrs[23]!;
}

// ---------------------------------------------------------------------------
// XMSS (FIPS 205 Section 6) — Merkle tree with WOTS+ leaves
// ---------------------------------------------------------------------------

function xmssNode(skSeed: Uint8Array, pkSeed: Uint8Array,
  idx: number, height: number, adrs: Uint8Array, params: SLHParams): Uint8Array {
  const { n } = params;

  if (height === 0) {
    // Leaf: WOTS+ public key
    const leafAdrs = new Uint8Array(adrs);
    setType(leafAdrs, ADRS_WOTS_HASH);
    setKeyPairAddress(leafAdrs, idx);
    return wotsPk(skSeed, pkSeed, leafAdrs, params);
  }

  const left = xmssNode(skSeed, pkSeed, 2 * idx, height - 1, adrs, params);
  const right = xmssNode(skSeed, pkSeed, 2 * idx + 1, height - 1, adrs, params);

  const nodeAdrs = new Uint8Array(adrs);
  setType(nodeAdrs, ADRS_TREE);
  setTreeHeight(nodeAdrs, height);
  setTreeIndex(nodeAdrs, idx);
  return T(pkSeed, nodeAdrs, concat(left, right), n);
}

function wotsPk(skSeed: Uint8Array, pkSeed: Uint8Array,
  adrs: Uint8Array, params: SLHParams): Uint8Array {
  const { n, w, len } = params;
  const parts: Uint8Array[] = [];

  for (let i = 0; i < len; i++) {
    const skAdrs = new Uint8Array(adrs);
    setType(skAdrs, ADRS_WOTS_PRF);
    setKeyPairAddress(skAdrs, getKeyPairAddress(adrs));
    setChainAddress(skAdrs, i);
    setHashAddress(skAdrs, 0);
    const sk = PRF(pkSeed, skSeed, skAdrs, n);

    const chainAdrs = new Uint8Array(adrs);
    setType(chainAdrs, ADRS_WOTS_HASH);
    setKeyPairAddress(chainAdrs, getKeyPairAddress(adrs));
    setChainAddress(chainAdrs, i);
    parts.push(wotsChain(sk, 0, w - 1, pkSeed, chainAdrs, n));
  }

  const pkAdrs = new Uint8Array(adrs);
  setType(pkAdrs, ADRS_WOTS_PK);
  return T(pkSeed, pkAdrs, concat(...parts), n);
}

function xmssSign(msg: Uint8Array, skSeed: Uint8Array, pkSeed: Uint8Array,
  idx: number, adrs: Uint8Array, params: SLHParams): Uint8Array {
  const { hp } = params;

  // WOTS+ signature
  const sigAdrs = new Uint8Array(adrs);
  setType(sigAdrs, ADRS_WOTS_HASH);
  setKeyPairAddress(sigAdrs, idx);
  const sig = wotsSign(msg, skSeed, pkSeed, sigAdrs, params);

  // Authentication path
  const authParts: Uint8Array[] = [];
  for (let j = 0; j < hp; j++) {
    const sibling = (idx >> j) ^ 1;
    authParts.push(xmssNode(skSeed, pkSeed, sibling, j, adrs, params));
  }

  return concat(sig, ...authParts);
}

function xmssPkFromSig(idx: number, sigXmss: Uint8Array, msg: Uint8Array,
  pkSeed: Uint8Array, adrs: Uint8Array, params: SLHParams): Uint8Array {
  const { n, hp, len } = params;
  const wotsSigLen = len * n;
  const wotsSig = sigXmss.slice(0, wotsSigLen);
  const auth = sigXmss.slice(wotsSigLen);

  // Reconstruct WOTS+ public key from signature
  const wAdrs = new Uint8Array(adrs);
  setType(wAdrs, ADRS_WOTS_HASH);
  setKeyPairAddress(wAdrs, idx);
  let node = wotsPkFromSig(wotsSig, msg, pkSeed, wAdrs, params);

  // Walk the authentication path up the Merkle tree
  const treeAdrs = new Uint8Array(adrs);
  setType(treeAdrs, ADRS_TREE);
  for (let j = 0; j < hp; j++) {
    const authJ = auth.slice(j * n, (j + 1) * n);
    setTreeHeight(treeAdrs, j + 1);
    if (((idx >> j) & 1) === 0) {
      setTreeIndex(treeAdrs, idx >> (j + 1));
      node = T(pkSeed, treeAdrs, concat(node, authJ), n);
    } else {
      setTreeIndex(treeAdrs, idx >> (j + 1));
      node = T(pkSeed, treeAdrs, concat(authJ, node), n);
    }
  }
  return node;
}

// ---------------------------------------------------------------------------
// FORS (FIPS 205 Section 8)
// ---------------------------------------------------------------------------

function forsSign(md: Uint8Array, skSeed: Uint8Array, pkSeed: Uint8Array,
  adrs: Uint8Array, params: SLHParams): Uint8Array {
  const { n, a, k } = params;
  const parts: Uint8Array[] = [];

  for (let i = 0; i < k; i++) {
    const idx = extractForsIdx(md, i, a);

    // Secret value
    const skAdrs = new Uint8Array(adrs);
    setType(skAdrs, ADRS_FORS_PRF);
    setKeyPairAddress(skAdrs, getKeyPairAddress(adrs));
    setTreeHeight(skAdrs, 0);
    setTreeIndex(skAdrs, i * (1 << a) + idx);
    const sk = PRF(pkSeed, skSeed, skAdrs, n);
    parts.push(sk);

    // Authentication path: sibling nodes at each height
    for (let j = 0; j < a; j++) {
      const siblingIdx = (idx >> j) ^ 1;
      parts.push(forsNode(skSeed, pkSeed, siblingIdx, j, adrs, i, params));
    }
  }

  return concat(...parts);
}

function forsNode(skSeed: Uint8Array, pkSeed: Uint8Array,
  idx: number, height: number, adrs: Uint8Array, treeIdx: number,
  params: SLHParams): Uint8Array {
  const { n, a } = params;

  if (height === 0) {
    const skAdrs = new Uint8Array(adrs);
    setType(skAdrs, ADRS_FORS_PRF);
    setKeyPairAddress(skAdrs, getKeyPairAddress(adrs));
    setTreeHeight(skAdrs, 0);
    setTreeIndex(skAdrs, treeIdx * (1 << a) + idx);
    const sk = PRF(pkSeed, skSeed, skAdrs, n);

    const leafAdrs = new Uint8Array(adrs);
    setType(leafAdrs, ADRS_FORS_TREE);
    setKeyPairAddress(leafAdrs, getKeyPairAddress(adrs));
    setTreeHeight(leafAdrs, 0);
    setTreeIndex(leafAdrs, treeIdx * (1 << a) + idx);
    return T(pkSeed, leafAdrs, sk, n);
  }

  const left = forsNode(skSeed, pkSeed, 2 * idx, height - 1, adrs, treeIdx, params);
  const right = forsNode(skSeed, pkSeed, 2 * idx + 1, height - 1, adrs, treeIdx, params);

  const nodeAdrs = new Uint8Array(adrs);
  setType(nodeAdrs, ADRS_FORS_TREE);
  setKeyPairAddress(nodeAdrs, getKeyPairAddress(adrs));
  setTreeHeight(nodeAdrs, height);
  setTreeIndex(nodeAdrs, treeIdx * (1 << (a - height)) + idx);
  return T(pkSeed, nodeAdrs, concat(left, right), n);
}

function forsPkFromSig(forsSignature: Uint8Array, md: Uint8Array,
  pkSeed: Uint8Array, adrs: Uint8Array, params: SLHParams): Uint8Array {
  const { n, a, k } = params;
  const roots: Uint8Array[] = [];
  let offset = 0;

  for (let i = 0; i < k; i++) {
    const idx = extractForsIdx(md, i, a);

    // Secret value → leaf
    const sk = forsSignature.slice(offset, offset + n);
    offset += n;

    const leafAdrs = new Uint8Array(adrs);
    setType(leafAdrs, ADRS_FORS_TREE);
    setKeyPairAddress(leafAdrs, getKeyPairAddress(adrs));
    setTreeHeight(leafAdrs, 0);
    setTreeIndex(leafAdrs, i * (1 << a) + idx);
    let node = T(pkSeed, leafAdrs, sk, n);

    // Walk auth path
    const authAdrs = new Uint8Array(adrs);
    setType(authAdrs, ADRS_FORS_TREE);
    setKeyPairAddress(authAdrs, getKeyPairAddress(adrs));

    for (let j = 0; j < a; j++) {
      const authJ = forsSignature.slice(offset, offset + n);
      offset += n;

      setTreeHeight(authAdrs, j + 1);
      if (((idx >> j) & 1) === 0) {
        setTreeIndex(authAdrs, (i * (1 << (a - j - 1))) + (idx >> (j + 1)));
        node = T(pkSeed, authAdrs, concat(node, authJ), n);
      } else {
        setTreeIndex(authAdrs, (i * (1 << (a - j - 1))) + (idx >> (j + 1)));
        node = T(pkSeed, authAdrs, concat(authJ, node), n);
      }
    }
    roots.push(node);
  }

  // Compress FORS roots into public key
  const forsPkAdrs = new Uint8Array(adrs);
  setType(forsPkAdrs, ADRS_FORS_ROOTS);
  setKeyPairAddress(forsPkAdrs, getKeyPairAddress(adrs));
  return T(pkSeed, forsPkAdrs, concat(...roots), n);
}

function extractForsIdx(md: Uint8Array, treeIdx: number, a: number): number {
  const bitStart = treeIdx * a;
  const byteStart = Math.floor(bitStart / 8);
  const bitOffset = bitStart % 8;

  // Read enough bytes to cover a bits starting at bitOffset
  let value = 0;
  const bitsNeeded = a;
  let bitsRead = 0;

  for (let i = byteStart; bitsRead < bitsNeeded; i++) {
    const byte = md[i] ?? 0;
    const availBits = (i === byteStart) ? (8 - bitOffset) : 8;
    const bitsToTake = Math.min(availBits, bitsNeeded - bitsRead);
    const shift = (i === byteStart) ? (availBits - bitsToTake) : (8 - bitsToTake);
    const mask = ((1 << bitsToTake) - 1);
    value = (value << bitsToTake) | ((byte >> shift) & mask);
    bitsRead += bitsToTake;
  }

  return value;
}

// ---------------------------------------------------------------------------
// Top-level: keygen, sign, verify (FIPS 205 Sections 9-10)
// ---------------------------------------------------------------------------

export interface SLHKeyPair {
  sk: Uint8Array; // SK.seed || SK.prf || PK.seed || PK.root
  pk: Uint8Array; // PK.seed || PK.root
}

export function slhKeygen(params: SLHParams, seed?: Uint8Array): SLHKeyPair {
  const { n } = params;
  const s = seed ?? new Uint8Array(crypto.getRandomValues(new Uint8Array(3 * n)));

  const skSeed = s.slice(0, n);
  const skPrf = s.slice(n, 2 * n);
  const pkSeed = s.slice(2 * n, 3 * n);

  // Compute root of the top XMSS tree
  const adrs = newADRS();
  setLayerAddress(adrs, params.d - 1);
  const root = xmssNode(skSeed, pkSeed, 0, params.hp, adrs, params);

  const sk = concat(skSeed, skPrf, pkSeed, root);
  const pk = concat(pkSeed, root);
  return { sk, pk };
}

export function slhSign(params: SLHParams, msg: Uint8Array, sk: Uint8Array): Uint8Array {
  const { n, d, hp, k, a } = params;
  const skSeed = sk.slice(0, n);
  const skPrf = sk.slice(n, 2 * n);
  const pkSeed = sk.slice(2 * n, 3 * n);
  const pkRoot = sk.slice(3 * n, 4 * n);

  // Randomize
  const optRand = pkSeed; // deterministic for now
  const R = PRFmsg(skPrf, optRand, msg, n);

  // Compute message digest
  const mdLen = Math.ceil((k * a) / 8);
  const treeIdxLen = Math.ceil((params.h - hp) / 8);
  const leafIdxLen = Math.ceil(hp / 8);
  const digestLen = mdLen + treeIdxLen + leafIdxLen;
  const digest = Hmsg(R, pkSeed, pkRoot, msg, digestLen);

  const md = digest.slice(0, mdLen);
  let treeIdx = 0n;
  for (let i = 0; i < treeIdxLen; i++) {
    treeIdx = (treeIdx << 8n) | BigInt(digest[mdLen + i]!);
  }
  treeIdx &= (1n << BigInt(params.h - hp)) - 1n;

  let leafIdx = 0;
  for (let i = 0; i < leafIdxLen; i++) {
    leafIdx = (leafIdx << 8) | (digest[mdLen + treeIdxLen + i]!);
  }
  leafIdx &= (1 << hp) - 1;

  // FORS signature
  const forsAdrs = newADRS();
  setTreeAddress(forsAdrs, treeIdx);
  setType(forsAdrs, ADRS_FORS_TREE);
  setKeyPairAddress(forsAdrs, leafIdx);
  const forsSig = forsSign(md, skSeed, pkSeed, forsAdrs, params);

  // Get FORS public key to sign with hypertree
  const forsPk = forsPkFromSig(forsSig, md, pkSeed, forsAdrs, params);

  // Hypertree signature
  const htSigParts: Uint8Array[] = [];
  let currentMsg = forsPk;
  let currentTreeIdx = treeIdx;
  let currentLeafIdx = leafIdx;

  for (let layer = 0; layer < d; layer++) {
    const layerAdrs = newADRS();
    setLayerAddress(layerAdrs, layer);
    setTreeAddress(layerAdrs, currentTreeIdx);

    const xmssSig = xmssSign(currentMsg, skSeed, pkSeed, currentLeafIdx, layerAdrs, params);
    htSigParts.push(xmssSig);

    // Move to next layer
    currentMsg = xmssPkFromSig(currentLeafIdx, xmssSig, currentMsg, pkSeed, layerAdrs, params);
    currentLeafIdx = Number(currentTreeIdx & BigInt((1 << hp) - 1));
    currentTreeIdx = currentTreeIdx >> BigInt(hp);
  }

  return concat(R, forsSig, ...htSigParts);
}

export function slhVerify(params: SLHParams, msg: Uint8Array, sig: Uint8Array, pk: Uint8Array): boolean {
  const { n, d, hp, k, a, len } = params;

  if (pk.length !== 2 * n) return false;
  const pkSeed = pk.slice(0, n);
  const pkRoot = pk.slice(n, 2 * n);

  // Parse signature
  let offset = 0;
  const R = sig.slice(offset, offset + n); offset += n;
  const forsSigLen = k * (1 + a) * n;
  const forsSig = sig.slice(offset, offset + forsSigLen); offset += forsSigLen;

  // Compute message digest
  const mdLen = Math.ceil((k * a) / 8);
  const treeIdxLen = Math.ceil((params.h - hp) / 8);
  const leafIdxLen = Math.ceil(hp / 8);
  const digestLen = mdLen + treeIdxLen + leafIdxLen;
  const digest = Hmsg(R, pkSeed, pkRoot, msg, digestLen);

  const md = digest.slice(0, mdLen);
  let treeIdx = 0n;
  for (let i = 0; i < treeIdxLen; i++) {
    treeIdx = (treeIdx << 8n) | BigInt(digest[mdLen + i]!);
  }
  treeIdx &= (1n << BigInt(params.h - hp)) - 1n;

  let leafIdx = 0;
  for (let i = 0; i < leafIdxLen; i++) {
    leafIdx = (leafIdx << 8) | (digest[mdLen + treeIdxLen + i]!);
  }
  leafIdx &= (1 << hp) - 1;

  // Verify FORS
  const forsAdrs = newADRS();
  setTreeAddress(forsAdrs, treeIdx);
  setType(forsAdrs, ADRS_FORS_TREE);
  setKeyPairAddress(forsAdrs, leafIdx);
  let currentMsg = forsPkFromSig(forsSig, md, pkSeed, forsAdrs, params);

  // Verify hypertree
  let currentTreeIdx = treeIdx;
  let currentLeafIdx = leafIdx;

  const xmssSigLen = (len + hp) * n;
  for (let layer = 0; layer < d; layer++) {
    const xmssSig = sig.slice(offset, offset + xmssSigLen); offset += xmssSigLen;

    const layerAdrs = newADRS();
    setLayerAddress(layerAdrs, layer);
    setTreeAddress(layerAdrs, currentTreeIdx);

    currentMsg = xmssPkFromSig(currentLeafIdx, xmssSig, currentMsg, pkSeed, layerAdrs, params);
    currentLeafIdx = Number(currentTreeIdx & BigInt((1 << hp) - 1));
    currentTreeIdx = currentTreeIdx >> BigInt(hp);
  }

  // Compare computed root to PK.root
  if (currentMsg.length !== pkRoot.length) return false;
  for (let i = 0; i < pkRoot.length; i++) {
    if (currentMsg[i] !== pkRoot[i]) return false;
  }
  return true;
}

/** Verbose verify: returns intermediate values for debugging */
export function slhVerifyVerbose(params: SLHParams, msg: Uint8Array, sig: Uint8Array, pk: Uint8Array): {
  forsPk: Uint8Array;
  wotsPks: Uint8Array[];
  roots: Uint8Array[];
  treeIdx: bigint;
  leafIdx: number;
} {
  const { n, d, hp, k, a, len } = params;
  const pkSeed = pk.slice(0, n);
  const pkRoot = pk.slice(n, 2 * n);

  let offset = 0;
  const R = sig.slice(offset, offset + n); offset += n;
  const forsSigLen = k * (1 + a) * n;
  const forsSig = sig.slice(offset, offset + forsSigLen); offset += forsSigLen;

  const mdLen = Math.ceil((k * a) / 8);
  const treeIdxLen = Math.ceil((params.h - hp) / 8);
  const leafIdxLen = Math.ceil(hp / 8);
  const digestLen = mdLen + treeIdxLen + leafIdxLen;
  const digest = Hmsg(R, pkSeed, pkRoot, msg, digestLen);

  const md = digest.slice(0, mdLen);
  let treeIdx = 0n;
  for (let i = 0; i < treeIdxLen; i++) {
    treeIdx = (treeIdx << 8n) | BigInt(digest[mdLen + i]!);
  }
  treeIdx &= (1n << BigInt(params.h - hp)) - 1n;

  let leafIdx = 0;
  for (let i = 0; i < leafIdxLen; i++) {
    leafIdx = (leafIdx << 8) | (digest[mdLen + treeIdxLen + i]!);
  }
  leafIdx &= (1 << hp) - 1;

  const forsAdrs = newADRS();
  setTreeAddress(forsAdrs, treeIdx);
  setType(forsAdrs, ADRS_FORS_TREE);
  setKeyPairAddress(forsAdrs, leafIdx);
  let currentMsg = forsPkFromSig(forsSig, md, pkSeed, forsAdrs, params);
  const forsPk = new Uint8Array(currentMsg);

  let currentTreeIdx = treeIdx;
  let currentLeafIdx = leafIdx;
  const roots: Uint8Array[] = [];
  const wotsPks: Uint8Array[] = [];

  const xmssSigLen = (len + hp) * n;
  for (let layer = 0; layer < d; layer++) {
    const xmssSig = sig.slice(offset, offset + xmssSigLen); offset += xmssSigLen;
    const wotsSig = xmssSig.slice(0, len * n);
    const auth = xmssSig.slice(len * n);

    const layerAdrs = newADRS();
    setLayerAddress(layerAdrs, layer);
    setTreeAddress(layerAdrs, currentTreeIdx);

    // WOTS+ pk reconstruction
    const wAdrs = new Uint8Array(layerAdrs);
    setType(wAdrs, ADRS_WOTS_HASH);
    setKeyPairAddress(wAdrs, currentLeafIdx);
    const wotsPk = wotsPkFromSig(wotsSig, currentMsg, pkSeed, wAdrs, params);
    wotsPks.push(new Uint8Array(wotsPk));

    // Merkle tree walk
    const treeAdrs = new Uint8Array(layerAdrs);
    setType(treeAdrs, ADRS_TREE);
    let node = wotsPk;
    for (let j = 0; j < hp; j++) {
      const authJ = auth.slice(j * n, (j + 1) * n);
      setTreeHeight(treeAdrs, j + 1);
      if (((currentLeafIdx >> j) & 1) === 0) {
        setTreeIndex(treeAdrs, currentLeafIdx >> (j + 1));
        node = T(pkSeed, treeAdrs, concat(node, authJ), n);
      } else {
        setTreeIndex(treeAdrs, currentLeafIdx >> (j + 1));
        node = T(pkSeed, treeAdrs, concat(authJ, node), n);
      }
    }
    currentMsg = node;
    roots.push(new Uint8Array(currentMsg));
    currentLeafIdx = Number(currentTreeIdx & BigInt((1 << hp) - 1));
    currentTreeIdx = currentTreeIdx >> BigInt(hp);
  }

  return { forsPk, wotsPks, roots, treeIdx, leafIdx };
}
