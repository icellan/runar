// ---------------------------------------------------------------------------
// runar-lang/types.ts — Domain types for Rúnar smart contracts
// ---------------------------------------------------------------------------
// Uses TypeScript branded types to enforce distinct semantic meanings at the
// type level. The Bitcoin SV script VM operates on byte strings and integers;
// these branded wrappers prevent accidental misuse (e.g. passing a raw hash
// where a public key is expected).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Branded type helpers
// ---------------------------------------------------------------------------

/** Unique symbol brands — one per domain type. */
declare const ByteStringBrand: unique symbol;
declare const PubKeyBrand: unique symbol;
declare const SigBrand: unique symbol;
declare const Ripemd160Brand: unique symbol;
declare const Sha256Brand: unique symbol;
declare const SigHashPreimageBrand: unique symbol;
declare const OpCodeTypeBrand: unique symbol;
declare const PointBrand: unique symbol;

// ---------------------------------------------------------------------------
// Core branded types
// ---------------------------------------------------------------------------

/**
 * An arbitrary-length hex-encoded byte string.
 * All higher-level byte types (PubKey, Sig, …) extend this.
 */
export type ByteString = string & { readonly [ByteStringBrand]: 'ByteString' };

/** 33-byte compressed public key (hex-encoded, 66 hex chars). */
export type PubKey = ByteString & { readonly [PubKeyBrand]: 'PubKey' };

/** DER-encoded ECDSA signature (hex-encoded). */
export type Sig = ByteString & { readonly [SigBrand]: 'Sig' };

/** RIPEMD-160 hash digest — 20 bytes (40 hex chars). */
export type Ripemd160 = ByteString & { readonly [Ripemd160Brand]: 'Ripemd160' };

/** SHA-256 hash digest — 32 bytes (64 hex chars). */
export type Sha256 = ByteString & { readonly [Sha256Brand]: 'Sha256' };

/** Bitcoin address = Hash160(pubkey) = RIPEMD-160(SHA-256(pubkey)). */
export type Addr = Ripemd160;

/** Sighash type flag — an integer carried as bigint. */
export type SigHashType = bigint;

/** The serialized sighash preimage fed to OP_CHECKSIG. */
export type SigHashPreimage = ByteString & {
  readonly [SigHashPreimageBrand]: 'SigHashPreimage';
};

/** Rabin signature — a large integer. */
export type RabinSig = bigint;

/** Rabin public key — a large integer (product of two primes). */
export type RabinPubKey = bigint;

/** Opcode encoded as a single-byte hex string. */
export type OpCodeType = ByteString & { readonly [OpCodeTypeBrand]: 'OpCodeType' };

/** Elliptic curve point — 64 bytes (x[32] || y[32], big-endian unsigned, no prefix). */
export type Point = ByteString & { readonly [PointBrand]: 'Point' };

// ---------------------------------------------------------------------------
// FixedArray<T, N> — compile-time fixed-size tuple
// ---------------------------------------------------------------------------

/**
 * Builds a tuple type of length `N` filled with `T`.
 *
 * ```ts
 * type ThreePubKeys = FixedArray<PubKey, 3>; // [PubKey, PubKey, PubKey]
 * ```
 *
 * The compiler recognises this type and emits sized-loop unrolling.  At the
 * type level it resolves to a real tuple so the developer gets index checks.
 */
export type FixedArray<T, N extends number> = N extends 0
  ? []
  : N extends 1
    ? [T]
    : N extends 2
      ? [T, T]
      : N extends 3
        ? [T, T, T]
        : N extends 4
          ? [T, T, T, T]
          : N extends 5
            ? [T, T, T, T, T]
            : N extends 6
              ? [T, T, T, T, T, T]
              : N extends 7
                ? [T, T, T, T, T, T, T]
                : N extends 8
                  ? [T, T, T, T, T, T, T, T]
                  : N extends 9
                    ? [T, T, T, T, T, T, T, T, T]
                    : N extends 10
                      ? [T, T, T, T, T, T, T, T, T, T]
                      : N extends 11
                        ? [T, T, T, T, T, T, T, T, T, T, T]
                        : N extends 12
                          ? [T, T, T, T, T, T, T, T, T, T, T, T]
                          : N extends 13
                            ? [T, T, T, T, T, T, T, T, T, T, T, T, T]
                            : N extends 14
                              ? [T, T, T, T, T, T, T, T, T, T, T, T, T, T]
                              : N extends 15
                                ? [T, T, T, T, T, T, T, T, T, T, T, T, T, T, T]
                                : N extends 16
                                  ? [T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T]
                                  : _BuildTuple<T, N>;

// Recursive helper for N > 16.  Real contracts rarely need more, but we
// support it so library authors aren't artificially limited.
type _BuildTuple<T, N extends number, R extends T[] = []> =
  R['length'] extends N ? R : _BuildTuple<T, N, [...R, T]>;

// ---------------------------------------------------------------------------
// Hex validation helper (internal)
// ---------------------------------------------------------------------------

const HEX_RE = /^([0-9a-fA-F]{2})*$/;

function assertValidHex(hex: string, label: string): void {
  if (!HEX_RE.test(hex)) {
    throw new Error(
      `${label}: expected an even-length hex string, got "${hex.length > 40 ? hex.slice(0, 40) + '…' : hex}"`,
    );
  }
}

function assertHexLength(hex: string, byteLen: number, label: string): void {
  assertValidHex(hex, label);
  const actual = hex.length / 2;
  if (actual !== byteLen) {
    throw new Error(`${label}: expected ${byteLen} bytes (${byteLen * 2} hex chars), got ${actual} bytes`);
  }
}

// ---------------------------------------------------------------------------
// Constructor / casting helpers
// ---------------------------------------------------------------------------

/**
 * Cast a hex string to `ByteString`. Validates that the input is
 * well-formed hex (even-length, only 0-9a-fA-F).
 */
export function toByteString(hex: string): ByteString {
  assertValidHex(hex, 'toByteString');
  return hex as ByteString;
}

/**
 * Cast a hex string to `PubKey`. Validates 33-byte compressed pubkey
 * (66 hex chars starting with 02 or 03).
 */
export function PubKey(hex: string): PubKey {
  assertHexLength(hex, 33, 'PubKey');
  const prefix = hex.slice(0, 2);
  if (prefix !== '02' && prefix !== '03') {
    throw new Error(`PubKey: expected compressed pubkey prefix 02 or 03, got ${prefix}`);
  }
  return hex as unknown as PubKey;
}

/**
 * Cast a hex string to `Sig`. Validates that the input looks like a
 * DER-encoded signature (starts with 0x30, minimum 8 bytes).
 */
export function Sig(hex: string): Sig {
  assertValidHex(hex, 'Sig');
  if (hex.length < 16) {
    throw new Error(`Sig: DER signature too short (${hex.length / 2} bytes)`);
  }
  if (hex.slice(0, 2) !== '30') {
    throw new Error(`Sig: expected DER prefix 0x30, got 0x${hex.slice(0, 2)}`);
  }
  return hex as unknown as Sig;
}

/**
 * Cast a hex string to `Ripemd160`. Validates 20 bytes.
 */
export function Ripemd160(hex: string): Ripemd160 {
  assertHexLength(hex, 20, 'Ripemd160');
  return hex as unknown as Ripemd160;
}

/**
 * Cast a hex string to `Sha256`. Validates 32 bytes.
 */
export function Sha256(hex: string): Sha256 {
  assertHexLength(hex, 32, 'Sha256');
  return hex as unknown as Sha256;
}

/**
 * Cast a hex string to `Addr` (alias for Ripemd160).
 */
export function Addr(hex: string): Addr {
  return Ripemd160(hex);
}

/**
 * Cast a hex string to `SigHashPreimage`.
 */
export function SigHashPreimage(hex: string): SigHashPreimage {
  assertValidHex(hex, 'SigHashPreimage');
  return hex as unknown as SigHashPreimage;
}

/**
 * Cast a hex string to `OpCodeType`.
 */
export function OpCodeType(hex: string): OpCodeType {
  assertValidHex(hex, 'OpCodeType');
  return hex as unknown as OpCodeType;
}

/**
 * Cast a hex string to `Point`. Validates 64 bytes (128 hex chars).
 */
export function Point(hex: string): Point {
  assertHexLength(hex, 64, 'Point');
  return hex as unknown as Point;
}

// ---------------------------------------------------------------------------
// SigHash constants
// ---------------------------------------------------------------------------

/**
 * Sighash flag constants used in Bitcoin SV transaction signing.
 *
 * Usage:
 * ```ts
 * const flags = SigHash.ALL | SigHash.FORKID;
 * ```
 */
export const SigHash = {
  /** Sign all inputs and all outputs. */
  ALL: 0x01n as SigHashType,
  /** Sign all inputs, no outputs (outputs can be changed). */
  NONE: 0x02n as SigHashType,
  /** Sign all inputs, only the output at the same index. */
  SINGLE: 0x03n as SigHashType,
  /**
   * Bitcoin SV / BCH fork-id flag. Must be OR-ed with one of ALL / NONE /
   * SINGLE for post-fork transactions.
   */
  FORKID: 0x40n as SigHashType,
  /**
   * If set, only the current input is signed — other inputs can be added or
   * removed by anyone.
   */
  ANYONECANPAY: 0x80n as SigHashType,
} as const;
