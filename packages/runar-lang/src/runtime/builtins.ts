// ---------------------------------------------------------------------------
// runar-lang/runtime/builtins.ts — Runtime-safe builtin implementations
// ---------------------------------------------------------------------------
// Working implementations of all Rúnar builtins for off-chain simulation.
// Crypto hashes use @bsv/sdk; signature verification returns true (mock);
// math uses native bigint; byte ops use hex string manipulation.
// ---------------------------------------------------------------------------

import { Hash, Signature, PublicKey } from '@bsv/sdk';
import type {
  ByteString,
  PubKey,
  Sig,
  Ripemd160,
  Sha256,
  RabinPubKey,
  RabinSig,
  Point,
  P256Point,
  P384Point,
} from '../types.js';

/** Fixed test message for real ECDSA verification in tests. */
const TEST_MESSAGE = Array.from(
  new TextEncoder().encode('runar-test-message-v1'),
);

// ---------------------------------------------------------------------------
// Hex ↔ Uint8Array helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return bytes;
}

function bytesToHex(bytes: number[] | Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

// ---------------------------------------------------------------------------
// Cryptographic hash functions
// ---------------------------------------------------------------------------

export function sha256(data: ByteString): Sha256 {
  const bytes = hexToBytes(data);
  const hash = Hash.sha256(bytes);
  return bytesToHex(hash) as unknown as Sha256;
}

export function ripemd160(data: ByteString): Ripemd160 {
  const bytes = hexToBytes(data);
  const hash = Hash.ripemd160(bytes);
  return bytesToHex(hash) as unknown as Ripemd160;
}

export function hash160(data: ByteString): Ripemd160 {
  const bytes = hexToBytes(data);
  const hash = Hash.hash160(bytes);
  return bytesToHex(hash) as unknown as Ripemd160;
}

export function hash256(data: ByteString): Sha256 {
  const bytes = hexToBytes(data);
  const hash = Hash.hash256(bytes);
  return bytesToHex(hash) as unknown as Sha256;
}

// ---------------------------------------------------------------------------
// Signature verification (real ECDSA over fixed test message)
// ---------------------------------------------------------------------------

/**
 * Parse a DER signature, stripping a trailing sighash byte if present.
 */
function parseDERSig(sigHex: string): InstanceType<typeof Signature> | null {
  try {
    const bytes = hexToBytes(sigHex);
    if (bytes.length < 8) return null;
    const declaredLen = bytes[1]!;
    const expectedPureDER = declaredLen + 2;
    let derBytes: number[];
    if (bytes.length === expectedPureDER) {
      derBytes = bytes;
    } else if (bytes.length === expectedPureDER + 1) {
      derBytes = bytes.slice(0, expectedPureDER);
    } else {
      derBytes = bytes;
    }
    return Signature.fromDER(derBytes);
  } catch {
    return null;
  }
}

export function checkSig(sig: Sig, pubkey: PubKey): boolean {
  try {
    const pk = PublicKey.fromDER(hexToBytes(pubkey as string));
    const parsedSig = parseDERSig(sig as string);
    if (!parsedSig) return false;
    return pk.verify(TEST_MESSAGE, parsedSig);
  } catch {
    return false;
  }
}

export function checkMultiSig(sigs: Sig[], pubkeys: PubKey[]): boolean {
  // Bitcoin's checkMultiSig: m sigs verified against n pubkeys in order
  let pkIdx = 0;
  for (const sig of sigs) {
    let found = false;
    while (pkIdx < pubkeys.length) {
      if (checkSig(sig, pubkeys[pkIdx]!)) {
        pkIdx++;
        found = true;
        break;
      }
      pkIdx++;
    }
    if (!found) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Byte-string operations
// ---------------------------------------------------------------------------

export function len(data: ByteString): bigint {
  return BigInt(data.length / 2);
}

export function cat(a: ByteString, b: ByteString): ByteString {
  return (a + b) as ByteString;
}

/**
 * N-171 (sibling of F-274): `substr` compiles to `<data> <start> OP_SPLIT
 * OP_NIP <length> OP_SPLIT OP_DROP` (lowerSubstr, 05-stack-lower.ts) — TWO
 * chained OP_SPLITs, the second against the REMAINDER `size(data) - start`.
 * It ABORTS whenever `start` is outside `[0, size(data)]` or `length` is
 * outside `[0, size(data) - start]`, which collapses to: `start < 0`,
 * `length < 0`, or `start + length > size(data)`. `.slice()` clamps instead
 * of aborting, so the bound is checked explicitly here.
 */
export function substr(data: ByteString, start: bigint, length: bigint): ByteString {
  const s = Number(start) * 2;
  const l = Number(length) * 2;
  if (start < 0n || length < 0n || s + l > data.length) {
    throw new Error(
      `substr: start ${start}, length ${length} is outside a ${data.length / 2}-byte value — ` +
        'OP_SPLIT aborts on a position below zero or past the end of the element, it does not clamp',
    );
  }
  return data.slice(s, s + l) as ByteString;
}

export function left(data: ByteString, length: bigint): ByteString {
  const n = Number(length) * 2;
  if (length < 0n || n > data.length) {
    throw new Error(
      `left: length ${length} is outside a ${data.length / 2}-byte value — OP_SPLIT aborts on a ` +
        'position below zero or past the end of the element, it does not clamp',
    );
  }
  return data.slice(0, n) as ByteString;
}

export function right(data: ByteString, length: bigint): ByteString {
  const n = Number(length) * 2;
  if (length < 0n || n > data.length) {
    throw new Error(
      `right: length ${length} is outside a ${data.length / 2}-byte value — OP_SPLIT aborts on a ` +
        'position below zero or past the end of the element, it does not clamp',
    );
  }
  return data.slice(data.length - n) as ByteString;
}

/**
 * The bytes from `index` onwards — the RIGHT half of the cut, which is what the
 * Rúnar builtin binds (`OP_SPLIT OP_NIP`). `left(data, index)` is the other
 * side. This used to return the `[left, right]` pair; nothing could name the
 * pair from contract source, and the signature disagreed with the frontend.
 *
 * N-171 (sibling of F-274): `split` is a bare `OP_SPLIT`, which ABORTS
 * whenever `index` is outside `[0, size(data)]`. `.slice()` clamps a
 * negative or past-the-end index instead of aborting, so the bound is
 * checked explicitly here.
 */
export function split(data: ByteString, index: bigint): ByteString {
  const n = Number(index) * 2;
  if (index < 0n || n > data.length) {
    throw new Error(
      `split: index ${index} is outside a ${data.length / 2}-byte value — OP_SPLIT aborts on a ` +
        'position below zero or past the end of the element, it does not clamp',
    );
  }
  return data.slice(n) as ByteString;
}

export function reverseBytes(data: ByteString): ByteString {
  const bytes = hexToBytes(data);
  bytes.reverse();
  return bytesToHex(bytes) as ByteString;
}

// ---------------------------------------------------------------------------
// Conversion — script number encoding
// ---------------------------------------------------------------------------

function encodeScriptNumber(n: bigint): number[] {
  if (n === 0n) return [];
  const negative = n < 0n;
  let abs = negative ? -n : n;
  const bytes: number[] = [];
  while (abs > 0n) {
    bytes.push(Number(abs & 0xffn));
    abs >>= 8n;
  }
  if (bytes[bytes.length - 1]! & 0x80) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1]! |= 0x80;
  }
  return bytes;
}

function decodeScriptNumber(bytes: number[] | Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  const last = bytes[bytes.length - 1]!;
  const negative = (last & 0x80) !== 0;
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]!);
  }
  if (negative) {
    // Clear sign bit
    result -= 1n << BigInt(bytes.length * 8 - 1);
  }
  return negative ? -result : result;
}

export function num2bin(value: bigint, byteLen: bigint): ByteString {
  const encoded = encodeScriptNumber(value);
  const result = new Array<number>(Number(byteLen)).fill(0);
  for (let i = 0; i < Math.min(encoded.length, result.length); i++) {
    result[i] = encoded[i]!;
  }
  if (encoded.length > 0 && encoded.length < result.length) {
    const lastByte = encoded[encoded.length - 1]!;
    if (lastByte & 0x80) {
      result[encoded.length - 1] = lastByte & 0x7f;
      result[result.length - 1] = 0x80;
    }
  }
  return bytesToHex(result) as ByteString;
}

export function bin2num(data: ByteString): bigint {
  const bytes = hexToBytes(data);
  return decodeScriptNumber(bytes);
}

export function int2str(value: bigint, byteLen: bigint): ByteString {
  return num2bin(value, byteLen);
}

// ---------------------------------------------------------------------------
// Assertion (same as the stub — works at runtime)
// ---------------------------------------------------------------------------

export { assert } from '../builtins.js';

// ---------------------------------------------------------------------------
// Math
// ---------------------------------------------------------------------------

export function abs(value: bigint): bigint {
  return value < 0n ? -value : value;
}

export function min(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

export function max(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
}

export function within(value: bigint, lo: bigint, hi: bigint): boolean {
  return value >= lo && value < hi;
}

export function safediv(a: bigint, b: bigint): bigint {
  if (b === 0n) throw new Error('safediv: division by zero');
  return a / b;
}

export function safemod(a: bigint, b: bigint): bigint {
  if (b === 0n) throw new Error('safemod: division by zero');
  return a % b;
}

export function clamp(value: bigint, lo: bigint, hi: bigint): bigint {
  // The compiled script is `<value> <lo> OP_MAX <hi> OP_MIN`, i.e.
  // min(max(value, lo), hi): with lo > hi, hi wins (N-030).
  const m = value > lo ? value : lo;
  return m < hi ? m : hi;
}

export function sign(value: bigint): bigint {
  if (value === 0n) return 0n;
  return value > 0n ? 1n : -1n;
}

export function pow(base: bigint, exp: bigint): bigint {
  if (exp < 0n) throw new Error('pow: negative exponent');
  // The compiled script guards `OP_DUP 0 33 OP_WITHIN OP_VERIFY` and ABORTS
  // for any exponent above 32, even where the power is trivial (F-134).
  if (exp > 32n) throw new Error('pow: exponent outside the supported domain (exp > 32)');
  let result = 1n;
  let b = base;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result *= b;
    b *= b;
    e >>= 1n;
  }
  return result;
}

export function mulDiv(a: bigint, b: bigint, c: bigint): bigint {
  return (a * b) / c;
}

export function percentOf(amount: bigint, bps: bigint): bigint {
  return (amount * bps) / 10000n;
}

export function sqrt(n: bigint): bigint {
  if (n < 0n) throw new Error('sqrt: negative input');
  // The compiled script VERIFYs OP_SIZE(n) < 63, i.e. n < 2^495 (F-134).
  if (n >= 1n << 495n) throw new Error('sqrt: input outside the supported domain (n >= 2^495)');
  if (n === 0n) return 0n;
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x;
}

export function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  // The compiled script unrolls exactly 256 Euclid steps and returns the
  // partial remainder when they are not enough (N-030).
  for (let i = 0; i < 256 && y !== 0n; i++) {
    const t = y;
    y = x % y;
    x = t;
  }
  return x;
}

export function divmod(a: bigint, b: bigint): bigint {
  return a / b;
}

export function log2(n: bigint): bigint {
  // The compiled script returns 0 for n <= 0 and unrolls exactly 64
  // halvings, so it saturates at 64 (N-030).
  if (n <= 0n) return 0n;
  let result = 0n;
  let v = n;
  while (v > 1n && result < 64n) {
    v >>= 1n;
    result++;
  }
  return result;
}

export function bool(value: bigint): boolean {
  return value !== 0n;
}

// ---------------------------------------------------------------------------
// Rabin signature verification (real)
// ---------------------------------------------------------------------------

function rabinBytesToUnsignedLE(bytes: number[]): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result += BigInt(bytes[i]!) << BigInt(i * 8);
  }
  return result;
}

/**
 * Upper bound (exclusive) on the Rabin `padding` parameter.
 *
 * Mirrors the on-chain `RABIN_PADDING_LIMIT` emitted by `EmitVerifyRabinSig`
 * (asserted via OP_WITHIN/OP_VERIFY) and the same bound already enforced by
 * packages/runar-testing's `rabinVerify` and the Go SDK's `rabin.go`. Without
 * it, sig=0 with padding=SHA256(msg) is a universal forgery: for ANY n,
 * (0^2 + SHA256(msg)) mod n == SHA256(msg) mod n trivially.
 */
const RABIN_PADDING_LIMIT = 65536n;

export function verifyRabinSig(
  msg: ByteString,
  sig: RabinSig,
  padding: ByteString,
  pubkey: RabinPubKey,
): boolean {
  if (pubkey <= 0n) return false;
  const msgBytes = hexToBytes(msg as string);
  const hashArr = Hash.sha256(msgBytes);
  const hashBN = rabinBytesToUnsignedLE(hashArr);
  const padBytes = hexToBytes(padding as string);
  const padBN = rabinBytesToUnsignedLE(padBytes);
  if (padBN >= RABIN_PADDING_LIMIT) return false;
  const lhs = ((sig * sig + padBN) % pubkey + pubkey) % pubkey;
  const rhs = (hashBN % pubkey + pubkey) % pubkey;
  return lhs === rhs;
}

// ---------------------------------------------------------------------------
// Post-quantum signature verification (mocked)
// ---------------------------------------------------------------------------

export function verifyWOTS(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

export function verifySLHDSA_SHA2_128s(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

export function verifySLHDSA_SHA2_128f(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

export function verifySLHDSA_SHA2_192s(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

export function verifySLHDSA_SHA2_192f(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

export function verifySLHDSA_SHA2_256s(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

export function verifySLHDSA_SHA2_256f(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

// ---------------------------------------------------------------------------
// Elliptic curve operations (secp256k1 via @bsv/sdk)
// ---------------------------------------------------------------------------

// N-111: these mirror the COMPILED script (ec-codegen.ts), gates included,
// rather than delegating to @bsv/sdk's Point, which has its own infinity
// object and never sees the all-zero blob as the identity. Vectors:
// packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json.

const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const EC_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const EC_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function ecFieldMod(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

/** Modular inverse; inv(0) = 0, as the script's Fermat inverse gives. */
function ecFieldInv(a: bigint, m: bigint): bigint {
  let [r0, r1] = [ecFieldMod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return ecFieldMod(s0, m);
}

/** CL-BUG-095: a Point is exactly 64 bytes, or the script aborts. */
function ecDecode(p: Point, fn: string): [bigint, bigint] {
  const h = p as string;
  if (h.length !== 128) {
    throw new Error(`${fn}: EC point must be 64 bytes, got ${h.length / 2}`);
  }
  return [BigInt('0x' + h.slice(0, 64)), BigInt('0x' + h.slice(64, 128))];
}

function ecEncode(x: bigint, y: bigint): Point {
  return (x.toString(16).padStart(64, '0') + y.toString(16).padStart(64, '0')) as unknown as Point;
}

/** R-117: ecAdd / ecNegate OP_VERIFY x < p and y < p. */
function ecRequireCanonical(x: bigint, y: bigint, fn: string): void {
  if (x >= EC_P || y >= EC_P) {
    throw new Error(`${fn}: point coordinate is not a canonical field element (x and y must be < p)`);
  }
}

/** The script's affineAdd: O selects, P + (-P) = O, tangent, chord. */
function ecAffineAdd(x1: bigint, y1: bigint, x2: bigint, y2: bigint): [bigint, bigint] {
  if (x1 === 0n && y1 === 0n) return [x2, y2];
  if (x2 === 0n && y2 === 0n) return [x1, y1];
  if (x1 === x2 && y1 !== y2) return [0n, 0n];
  const s = x1 === x2
    ? ecFieldMod(3n * x1 * x1 * ecFieldInv(2n * y1, EC_P), EC_P)
    : ecFieldMod((y2 - y1) * ecFieldInv(x2 - x1, EC_P), EC_P);
  const rx = ecFieldMod(s * s - x1 - x2, EC_P);
  const ry = ecFieldMod(s * (x1 - rx) - y1, EC_P);
  return [rx, ry];
}

function ecScalarMulCoords(x: bigint, y: bigint, k: bigint): [bigint, bigint] {
  let kr = ecFieldMod(k, EC_N);
  let rx = 0n;
  let ry = 0n;
  let ax = x;
  let ay = y;
  while (kr > 0n) {
    if (kr & 1n) [rx, ry] = ecAffineAdd(rx, ry, ax, ay);
    [ax, ay] = ecAffineAdd(ax, ay, ax, ay);
    kr >>= 1n;
  }
  return [rx, ry];
}

function ecOnCurveCoords(x: bigint, y: bigint): boolean {
  if (x >= EC_P || y >= EC_P) return false;
  return ecFieldMod(y * y, EC_P) === ecFieldMod(x * x * x + 7n, EC_P);
}

export function ecAdd(a: Point, b: Point): Point {
  const [ax, ay] = ecDecode(a, 'ecAdd');
  const [bx, by] = ecDecode(b, 'ecAdd');
  ecRequireCanonical(ax, ay, 'ecAdd');
  ecRequireCanonical(bx, by, 'ecAdd');
  const [rx, ry] = ecAffineAdd(ax, ay, bx, by);
  return ecEncode(rx, ry);
}

export function ecMul(p: Point, k: bigint): Point {
  const [x, y] = ecDecode(p, 'ecMul');
  // R-157: the script OP_VERIFYs `onCurve(P) OR P == O` before the ladder.
  if (!(x === 0n && y === 0n) && !ecOnCurveCoords(x, y)) {
    throw new Error('ecMul: point is neither on secp256k1 nor the point at infinity');
  }
  const [rx, ry] = ecScalarMulCoords(x, y, k);
  return ecEncode(rx, ry);
}

export function ecMulGen(k: bigint): Point {
  const [rx, ry] = ecScalarMulCoords(EC_GX, EC_GY, k);
  return ecEncode(rx, ry);
}

export function ecNegate(p: Point): Point {
  const [x, y] = ecDecode(p, 'ecNegate');
  ecRequireCanonical(x, y, 'ecNegate');
  return ecEncode(x, ecFieldMod(EC_P - y, EC_P));
}

export function ecOnCurve(p: Point): boolean {
  const h = p as string;
  // N-184: a predicate over untrusted bytes must stay total. The compiled
  // emitPointLengthGate ANDs a width flag into the result instead of
  // aborting, so a 63- or 65-byte blob is false, not computed on whatever
  // `slice` happens to return (a 65-byte blob used to re-slice the real
  // x, y out of the first 64 bytes and silently accept it — fail-open,
  // worse than a raise). ecAdd/ecMul/ecNegate still abort on the wrong
  // width via ecDecode; only this predicate stays total.
  if (h.length !== 128) return false;
  const x = BigInt('0x' + h.slice(0, 64));
  const y = BigInt('0x' + h.slice(64, 128));
  // GAP-301: reject non-canonical coordinate encodings (x ≥ p or y ≥ p). The
  // compiled script range-checks the coordinates before the field arithmetic
  // reduces them mod p, so the interpreter must too or it would accept a point
  // the on-chain script rejects.
  if (x >= EC_P || y >= EC_P) return false;
  const lhs = (y * y) % EC_P;
  const rhs = (x * x * x + 7n) % EC_P;
  return lhs === rhs;
}

export function ecModReduce(value: bigint, mod: bigint): bigint {
  return ((value % mod) + mod) % mod;
}

export function ecEncodeCompressed(p: Point): ByteString {
  const [, yBig] = ecDecode(p, 'ecEncodeCompressed');
  const prefix = yBig % 2n === 0n ? '02' : '03';
  return (prefix + (p as string).slice(0, 64)) as ByteString;
}

export function ecMakePoint(x: bigint, y: bigint): Point {
  const xHex = x.toString(16).padStart(64, '0');
  const yHex = y.toString(16).padStart(64, '0');
  return (xHex + yHex) as unknown as Point;
}

export function ecPointX(p: Point): bigint {
  return ecDecode(p, 'ecPointX')[0];
}

export function ecPointY(p: Point): bigint {
  return ecDecode(p, 'ecPointY')[1];
}

// ---------------------------------------------------------------------------
// P-256 (NIST P-256 / secp256r1) curve operations (mocked)
// ---------------------------------------------------------------------------
// Mock implementations return identity-like dummy values that won't crash.
// The real implementations are generated by the Rúnar compiler as Bitcoin Script.
// ---------------------------------------------------------------------------

/** Zero point for P-256 (not a valid curve point; used as a safe dummy). */
const P256_ZERO = '0'.repeat(128) as unknown as P256Point;

export function p256Add(_a: P256Point, _b: P256Point): P256Point {
  return P256_ZERO;
}

export function p256Mul(_p: P256Point, _k: bigint): P256Point {
  return P256_ZERO;
}

export function p256MulGen(_k: bigint): P256Point {
  return P256_ZERO;
}

export function p256Negate(_p: P256Point): P256Point {
  return P256_ZERO;
}

export function p256OnCurve(_p: P256Point): boolean {
  return true;
}

export function p256EncodeCompressed(_p: P256Point): ByteString {
  return ('02' + '0'.repeat(64)) as ByteString;
}

export function verifyECDSA_P256(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

// ---------------------------------------------------------------------------
// P-384 (NIST P-384 / secp384r1) curve operations (mocked)
// ---------------------------------------------------------------------------

/** Zero point for P-384 (not a valid curve point; used as a safe dummy). */
const P384_ZERO = '0'.repeat(192) as unknown as P384Point;

export function p384Add(_a: P384Point, _b: P384Point): P384Point {
  return P384_ZERO;
}

export function p384Mul(_p: P384Point, _k: bigint): P384Point {
  return P384_ZERO;
}

export function p384MulGen(_k: bigint): P384Point {
  return P384_ZERO;
}

export function p384Negate(_p: P384Point): P384Point {
  return P384_ZERO;
}

export function p384OnCurve(_p: P384Point): boolean {
  return true;
}

export function p384EncodeCompressed(_p: P384Point): ByteString {
  return ('02' + '0'.repeat(96)) as ByteString;
}

export function verifyECDSA_P384(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return true;
}

// ---------------------------------------------------------------------------
// Baby Bear field arithmetic (p = 2^31 - 2^27 + 1 = 2013265921)
// ---------------------------------------------------------------------------

const BB_P = 2013265921n;

export function bbFieldAdd(a: bigint, b: bigint): bigint {
  return (a + b) % BB_P;
}

export function bbFieldSub(a: bigint, b: bigint): bigint {
  return ((a - b) % BB_P + BB_P) % BB_P;
}

export function bbFieldMul(a: bigint, b: bigint): bigint {
  return (a * b) % BB_P;
}

export function bbFieldInv(a: bigint): bigint {
  // Fermat's little theorem: a^(p-2) mod p
  let result = 1n;
  let base = ((a % BB_P) + BB_P) % BB_P;
  let exp = BB_P - 2n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % BB_P;
    base = (base * base) % BB_P;
    exp >>= 1n;
  }
  return result;
}

// ---------------------------------------------------------------------------
// KoalaBear field arithmetic (p = 2^31 - 2^24 + 1 = 2,130,706,433)
// ---------------------------------------------------------------------------

const KB_P = 2130706433n;

export function kbFieldAdd(a: bigint, b: bigint): bigint {
  return (a + b) % KB_P;
}

export function kbFieldSub(a: bigint, b: bigint): bigint {
  return ((a - b) % KB_P + KB_P) % KB_P;
}

export function kbFieldMul(a: bigint, b: bigint): bigint {
  return (a * b) % KB_P;
}

export function kbFieldInv(a: bigint): bigint {
  let result = 1n;
  let base = ((a % KB_P) + KB_P) % KB_P;
  let exp = KB_P - 2n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % KB_P;
    base = (base * base) % KB_P;
    exp >>= 1n;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Merkle proof verification
// ---------------------------------------------------------------------------

export function merkleRootSha256(
  leaf: ByteString,
  proof: ByteString,
  index: bigint,
  depth: bigint,
): ByteString {
  return merkleRootImpl(leaf, proof, index, Number(depth), (data) =>
    Hash.sha256(hexToUint8Array(data as string)),
  );
}

export function merkleRootHash256(
  leaf: ByteString,
  proof: ByteString,
  index: bigint,
  depth: bigint,
): ByteString {
  return merkleRootImpl(leaf, proof, index, Number(depth), (data) =>
    Hash.sha256(Hash.sha256(hexToUint8Array(data as string))),
  );
}

function hexToUint8Array(hex: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return bytes;
}

function merkleRootImpl(
  leaf: ByteString,
  proof: ByteString,
  index: bigint,
  depth: number,
  hashFn: (data: ByteString) => number[],
): ByteString {
  let current = leaf as string;
  const proofStr = proof as string;

  for (let i = 0; i < depth; i++) {
    const sibling = proofStr.slice(i * 64, (i + 1) * 64);
    const bit = (index >> BigInt(i)) & 1n;
    const preimage = bit === 1n ? sibling + current : current + sibling;
    const hashBytes = hashFn(preimage as ByteString);
    current = hashBytes.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  return current as ByteString;
}
