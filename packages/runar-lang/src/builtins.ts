// ---------------------------------------------------------------------------
// runar-lang/builtins.ts — Built-in functions mapped to Bitcoin Script opcodes
// ---------------------------------------------------------------------------
// These functions exist so that contract authors can write readable TypeScript
// that the Rúnar compiler translates into the corresponding opcodes.  The
// runtime implementations are intentionally stubs — you cannot *execute* a
// smart contract outside of the Bitcoin VM.  The sole exception is `assert`,
// which works at runtime for testing convenience.
// ---------------------------------------------------------------------------

import type {
  ByteString,
  PubKey,
  Sig,
  Ripemd160,
  Sha256,
  RabinPubKey,
  RabinSig,
} from './types.js';

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

function compilerStub(name: string): never {
  throw new Error(
    `${name}() cannot be called at runtime — compile this contract with the Rúnar compiler.`,
  );
}

// ---------------------------------------------------------------------------
// Cryptographic hash functions
// ---------------------------------------------------------------------------

/**
 * SHA-256 hash.
 * Compiles to: `OP_SHA256`
 */
export function sha256(_data: ByteString): Sha256 {
  return compilerStub('sha256');
}

/**
 * RIPEMD-160 hash.
 * Compiles to: `OP_RIPEMD160`
 */
export function ripemd160(_data: ByteString): Ripemd160 {
  return compilerStub('ripemd160');
}

/**
 * Hash160 = RIPEMD-160(SHA-256(data)).
 * Compiles to: `OP_HASH160`
 */
export function hash160(_data: ByteString): Ripemd160 {
  return compilerStub('hash160');
}

/**
 * Hash256 = SHA-256(SHA-256(data)).
 * Compiles to: `OP_HASH256`
 */
export function hash256(_data: ByteString): Sha256 {
  return compilerStub('hash256');
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/**
 * Verify an ECDSA signature against a public key.
 * Compiles to: `OP_CHECKSIG`
 */
export function checkSig(_sig: Sig, _pubkey: PubKey): boolean {
  return compilerStub('checkSig');
}

/**
 * Verify m-of-n multi-signature.
 * Compiles to: `OP_CHECKMULTISIG`
 *
 * @param sigs   - Array of signatures (length = m).
 * @param pubkeys - Array of public keys (length = n).
 */
export function checkMultiSig(_sigs: Sig[], _pubkeys: PubKey[]): boolean {
  return compilerStub('checkMultiSig');
}

// ---------------------------------------------------------------------------
// Byte-string operations
// ---------------------------------------------------------------------------

/**
 * Length of a byte string in bytes.
 * Compiles to: `OP_SIZE`
 */
export function len(_data: ByteString): bigint {
  return compilerStub('len');
}

/**
 * Concatenate two byte strings.
 * Compiles to: `OP_CAT`
 */
export function cat(_a: ByteString, _b: ByteString): ByteString {
  return compilerStub('cat');
}

/**
 * Extract a substring.
 * Compiles to: `OP_SUBSTR` (if available) or `OP_SPLIT + OP_SPLIT + OP_NIP`.
 *
 * @param data  - Source byte string.
 * @param start - Zero-based byte offset.
 * @param len   - Number of bytes to extract.
 */
export function substr(_data: ByteString, _start: bigint, _len: bigint): ByteString {
  return compilerStub('substr');
}

/**
 * Take the leftmost `len` bytes.
 * Compiles to: `OP_SPLIT OP_DROP` (keep left part).
 */
export function left(_data: ByteString, _len: bigint): ByteString {
  return compilerStub('left');
}

/**
 * Returns the rightmost `len` bytes of a byte string.
 * Compiles to: `OP_SIZE <len> OP_SUB OP_SPLIT OP_NIP`
 * (computes split offset from end, keeps right part).
 */
export function right(_data: ByteString, _len: bigint): ByteString {
  return compilerStub('right');
}

/**
 * Split a byte string at position `index` into two parts.
 * Compiles to: `OP_SPLIT`
 *
 * @returns A tuple [left, right].
 */
export function split(_data: ByteString, _index: bigint): [ByteString, ByteString] {
  return compilerStub('split');
}

/**
 * Reverse byte order of a byte string.
 * Useful for endianness conversions (e.g. txid display vs internal order).
 * Compiled via a sequence of OP_SPLIT / OP_SWAP / OP_CAT operations.
 */
export function reverseBytes(_data: ByteString): ByteString {
  return compilerStub('reverseBytes');
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

/**
 * Convert a number to a byte string of a given byte length (little-endian).
 * Compiles to: `OP_NUM2BIN`
 */
export function num2bin(_value: bigint, _byteLen: bigint): ByteString {
  return compilerStub('num2bin');
}

/**
 * Convert a byte string (little-endian) to a script number.
 * Compiles to: `OP_BIN2NUM`
 */
export function bin2num(_data: ByteString): bigint {
  return compilerStub('bin2num');
}

/**
 * Convert an integer to its minimal-encoding byte-string representation.
 * Alias used in some contract idioms; compiles similarly to `num2bin`.
 */
export function int2str(_value: bigint, _byteLen: bigint): ByteString {
  return compilerStub('int2str');
}

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

/**
 * Assert a condition. If the condition is `false`, script execution fails.
 * Compiles to: `OP_VERIFY` (or `OP_EQUALVERIFY`, etc. when fused).
 *
 * Unlike the other builtins, `assert` **works at runtime** so that unit
 * tests can exercise contract logic without the compiler.
 */
export function assert(condition: boolean, message?: string): asserts condition {
  if (!condition) {
    throw new Error(message ?? 'assert failed');
  }
}

// ---------------------------------------------------------------------------
// Math
// ---------------------------------------------------------------------------

/**
 * Absolute value.
 * Compiles to: `OP_ABS`
 */
export function abs(_value: bigint): bigint {
  return compilerStub('abs');
}

/**
 * Minimum of two values.
 * Compiles to: `OP_MIN`
 */
export function min(_a: bigint, _b: bigint): bigint {
  return compilerStub('min');
}

/**
 * Maximum of two values.
 * Compiles to: `OP_MAX`
 */
export function max(_a: bigint, _b: bigint): bigint {
  return compilerStub('max');
}

/**
 * Returns `true` if `min <= value < max`.
 * Compiles to: `OP_WITHIN`
 */
export function within(_value: bigint, _min: bigint, _max: bigint): boolean {
  return compilerStub('within');
}

/**
 * Safe division — asserts the divisor is non-zero before dividing.
 * Compiles to: `OP_DUP OP_0NOTEQUAL OP_VERIFY OP_DIV`
 */
export function safediv(_a: bigint, _b: bigint): bigint {
  return compilerStub('safediv');
}

/**
 * Safe modulo — asserts the divisor is non-zero before taking modulo.
 * Compiles to: `OP_DUP OP_0NOTEQUAL OP_VERIFY OP_MOD`
 */
export function safemod(_a: bigint, _b: bigint): bigint {
  return compilerStub('safemod');
}

/**
 * Clamp a value to the range [lo, hi].
 * Compiles to: `<lo> OP_MAX <hi> OP_MIN`
 */
export function clamp(_value: bigint, _lo: bigint, _hi: bigint): bigint {
  return compilerStub('clamp');
}

/**
 * Sign of a number: returns -1, 0, or 1.
 * Guards against division by zero when value is 0.
 * Compiles to: `OP_DUP OP_IF OP_DUP OP_ABS OP_SWAP OP_DIV OP_ENDIF`
 */
export function sign(_value: bigint): bigint {
  return compilerStub('sign');
}

/**
 * Exponentiation.
 * For constant exponents, the compiler unrolls to repeated `OP_MUL`.
 * For runtime exponents, a bounded iteration is emitted.
 */
export function pow(_base: bigint, _exp: bigint): bigint {
  return compilerStub('pow');
}

/**
 * Multiply then divide: `(a * b) / c`.
 * Useful for ratio calculations without intermediate overflow concern.
 * Compiles to: `OP_MUL OP_DIV`
 */
export function mulDiv(_a: bigint, _b: bigint, _c: bigint): bigint {
  return compilerStub('mulDiv');
}

/**
 * Calculate a percentage in basis points: `(amount * bps) / 10000`.
 * Compiles to: `OP_MUL <10000> OP_DIV`
 */
export function percentOf(_amount: bigint, _bps: bigint): bigint {
  return compilerStub('percentOf');
}

/**
 * Integer square root via Newton's method (bounded iterations).
 */
export function sqrt(_n: bigint): bigint {
  return compilerStub('sqrt');
}

/**
 * Greatest common divisor via Euclidean algorithm (bounded iterations).
 */
export function gcd(_a: bigint, _b: bigint): bigint {
  return compilerStub('gcd');
}

/**
 * Division returning quotient.
 * Compiles to: `OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP`
 */
export function divmod(_a: bigint, _b: bigint): bigint {
  return compilerStub('divmod');
}

/**
 * Approximate floor(log2(n)) via byte size of script number encoding.
 * Compiles to: `OP_SIZE OP_NIP 8 OP_MUL 8 OP_SUB`
 */
export function log2(_n: bigint): bigint {
  return compilerStub('log2');
}

// ---------------------------------------------------------------------------
// Rabin signature verification (oracle support)
// ---------------------------------------------------------------------------

/**
 * Verify a Rabin signature.
 *
 * This is NOT a single opcode — the compiler emits an inlined Rabin
 * verification script (modular exponentiation via OP_MUL / OP_MOD).
 */
export function verifyRabinSig(
  _msg: ByteString,
  _sig: RabinSig,
  _padding: ByteString,
  _pubkey: RabinPubKey,
): boolean {
  return compilerStub('verifyRabinSig');
}

// ---------------------------------------------------------------------------
// Post-quantum signature verification (hash-based)
// ---------------------------------------------------------------------------

/**
 * Verify a WOTS+ (Winternitz One-Time Signature) signature.
 *
 * Uses SHA-256 with w=16, n=32. The compiler emits an inlined verification
 * script that extracts base-16 digits from the message hash, computes a
 * checksum, verifies 67 hash chains, and compares the reconstructed public
 * key.
 *
 * Signature size: 2,144 bytes (67 chains x 32 bytes).
 * Public key size: 32 bytes.
 * Estimated script size: ~12 KB.
 *
 * One-time use: each keypair can securely sign only one message.
 * This is a natural fit for Bitcoin's UTXO model where each output is spent
 * exactly once.
 *
 * @param msg    - The message to verify.
 * @param sig    - WOTS+ signature (2,144 bytes).
 * @param pubkey - WOTS+ public key (32 bytes).
 */
export function verifyWOTS(
  _msg: ByteString,
  _sig: ByteString,
  _pubkey: ByteString,
): boolean {
  return compilerStub('verifyWOTS');
}

/**
 * Verify an SLH-DSA-SHA2-128s (SPHINCS+) signature.
 * NIST FIPS 205, 128-bit security, small signatures (7,856 bytes).
 */
export function verifySLHDSA_SHA2_128s(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return compilerStub('verifySLHDSA_SHA2_128s');
}

/**
 * Verify an SLH-DSA-SHA2-128f (SPHINCS+) signature.
 * NIST FIPS 205, 128-bit security, fast signatures (17,088 bytes).
 */
export function verifySLHDSA_SHA2_128f(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return compilerStub('verifySLHDSA_SHA2_128f');
}

/**
 * Verify an SLH-DSA-SHA2-192s (SPHINCS+) signature.
 * NIST FIPS 205, 192-bit security, small signatures (16,224 bytes).
 */
export function verifySLHDSA_SHA2_192s(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return compilerStub('verifySLHDSA_SHA2_192s');
}

/**
 * Verify an SLH-DSA-SHA2-192f (SPHINCS+) signature.
 * NIST FIPS 205, 192-bit security, fast signatures (35,664 bytes).
 */
export function verifySLHDSA_SHA2_192f(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return compilerStub('verifySLHDSA_SHA2_192f');
}

/**
 * Verify an SLH-DSA-SHA2-256s (SPHINCS+) signature.
 * NIST FIPS 205, 256-bit security, small signatures (29,792 bytes).
 */
export function verifySLHDSA_SHA2_256s(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return compilerStub('verifySLHDSA_SHA2_256s');
}

/**
 * Verify an SLH-DSA-SHA2-256f (SPHINCS+) signature.
 * NIST FIPS 205, 256-bit security, fast signatures (49,856 bytes).
 */
export function verifySLHDSA_SHA2_256f(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return compilerStub('verifySLHDSA_SHA2_256f');
}
