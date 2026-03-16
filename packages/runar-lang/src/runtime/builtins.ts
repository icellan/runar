// ---------------------------------------------------------------------------
// runar-lang/runtime/builtins.ts — Runtime-safe builtin implementations
// ---------------------------------------------------------------------------
// Working implementations of all Rúnar builtins for off-chain simulation.
// Crypto hashes use @bsv/sdk; signature verification returns true (mock);
// math uses native bigint; byte ops use hex string manipulation.
// ---------------------------------------------------------------------------

import { Hash, Point as BsvPoint, BigNumber, Signature, PublicKey } from '@bsv/sdk';
import type {
  ByteString,
  PubKey,
  Sig,
  Ripemd160,
  Sha256,
  RabinPubKey,
  RabinSig,
  Point,
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

export function substr(data: ByteString, start: bigint, length: bigint): ByteString {
  const s = Number(start) * 2;
  const l = Number(length) * 2;
  return data.slice(s, s + l) as ByteString;
}

export function left(data: ByteString, length: bigint): ByteString {
  return data.slice(0, Number(length) * 2) as ByteString;
}

export function right(data: ByteString, length: bigint): ByteString {
  return data.slice(data.length - Number(length) * 2) as ByteString;
}

export function split(data: ByteString, index: bigint): [ByteString, ByteString] {
  const i = Number(index) * 2;
  return [data.slice(0, i) as ByteString, data.slice(i) as ByteString];
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
  if (value < lo) return lo;
  if (value > hi) return hi;
  return value;
}

export function sign(value: bigint): bigint {
  if (value === 0n) return 0n;
  return value > 0n ? 1n : -1n;
}

export function pow(base: bigint, exp: bigint): bigint {
  if (exp < 0n) throw new Error('pow: negative exponent');
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
  while (y !== 0n) {
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
  if (n <= 0n) throw new Error('log2: non-positive input');
  let result = 0n;
  let v = n;
  while (v > 1n) {
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

function toBsvPoint(p: Point): BsvPoint {
  const xHex = (p as string).slice(0, 64);
  const yHex = (p as string).slice(64, 128);
  return new BsvPoint(xHex, yHex);
}

function fromBsvPoint(p: BsvPoint): Point {
  return (p.getX().toHex(32) + p.getY().toHex(32)) as unknown as Point;
}

const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;

export function ecAdd(a: Point, b: Point): Point {
  return fromBsvPoint(toBsvPoint(a).add(toBsvPoint(b)));
}

export function ecMul(p: Point, k: bigint): Point {
  return fromBsvPoint(toBsvPoint(p).mul(new BigNumber(k.toString())));
}

export function ecMulGen(k: bigint): Point {
  const G = new BsvPoint(
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
  );
  return fromBsvPoint(G.mul(new BigNumber(k.toString())));
}

export function ecNegate(p: Point): Point {
  const bsv = toBsvPoint(p);
  const yBig = BigInt('0x' + bsv.getY().toHex(32));
  const negY = EC_P - yBig;
  const negYHex = negY.toString(16).padStart(64, '0');
  return (bsv.getX().toHex(32) + negYHex) as unknown as Point;
}

export function ecOnCurve(p: Point): boolean {
  const x = BigInt('0x' + (p as string).slice(0, 64));
  const y = BigInt('0x' + (p as string).slice(64, 128));
  const lhs = (y * y) % EC_P;
  const rhs = (x * x * x + 7n) % EC_P;
  return lhs === rhs;
}

export function ecModReduce(value: bigint, mod: bigint): bigint {
  return ((value % mod) + mod) % mod;
}

export function ecEncodeCompressed(p: Point): ByteString {
  const yBig = BigInt('0x' + (p as string).slice(64, 128));
  const prefix = yBig % 2n === 0n ? '02' : '03';
  return (prefix + (p as string).slice(0, 64)) as ByteString;
}

export function ecMakePoint(x: bigint, y: bigint): Point {
  const xHex = x.toString(16).padStart(64, '0');
  const yHex = y.toString(16).padStart(64, '0');
  return (xHex + yHex) as unknown as Point;
}

export function ecPointX(p: Point): bigint {
  return BigInt('0x' + (p as string).slice(0, 64));
}

export function ecPointY(p: Point): bigint {
  return BigInt('0x' + (p as string).slice(64, 128));
}
