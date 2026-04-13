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
  Point,
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

/**
 * One round of SHA-256 compression.
 * Takes a 32-byte intermediate state and a 64-byte message block,
 * returns the 32-byte updated state.
 * Compiled to inlined SHA-256 compression opcodes (~3000 ops).
 */
export function sha256Compress(_state: ByteString, _block: ByteString): ByteString {
  return compilerStub('sha256Compress');
}

/**
 * Finalize a partial SHA-256 hash.
 * Takes the intermediate state, remaining message bytes (< 64 bytes),
 * and the total message bit length. Applies SHA-256 padding and runs
 * the final 1-2 compression rounds.
 */
export function sha256Finalize(_state: ByteString, _remaining: ByteString, _msgBitLen: bigint): ByteString {
  return compilerStub('sha256Finalize');
}

/**
 * BLAKE3 single-block compression.
 * Takes a 32-byte chaining value and a 64-byte message block.
 * Returns the 32-byte hash output.
 * Compiled to inlined BLAKE3 compression opcodes.
 */
export function blake3Compress(_chainingValue: ByteString, _block: ByteString): ByteString {
  return compilerStub('blake3Compress');
}

/**
 * Full BLAKE3 hash for messages up to 64 bytes.
 * Uses the IV as the chaining value, applies zero-padding,
 * and returns the 32-byte hash.
 */
export function blake3Hash(_message: ByteString): ByteString {
  return compilerStub('blake3Hash');
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
 * Approximate floor(log2(n)) via bit-scanning.
 * Compiles to a 64-iteration bit-scanning loop.
 */
export function log2(_n: bigint): bigint {
  return compilerStub('log2');
}

/**
 * Convert a number to a boolean: 0n is false, non-zero is true.
 * Compiles to: `OP_0NOTEQUAL`
 */
export function bool(_value: bigint): boolean {
  return compilerStub('bool');
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
 * NIST FIPS 205, 256-bit security, fast signatures (48,736 bytes).
 */
export function verifySLHDSA_SHA2_256f(_msg: ByteString, _sig: ByteString, _pubkey: ByteString): boolean {
  return compilerStub('verifySLHDSA_SHA2_256f');
}

// ---------------------------------------------------------------------------
// Elliptic curve point operations (secp256k1)
// ---------------------------------------------------------------------------

/**
 * Add two elliptic curve points.
 * Compiled to inlined affine point addition using modular arithmetic opcodes.
 */
export function ecAdd(_a: Point, _b: Point): Point {
  return compilerStub('ecAdd');
}

/**
 * Scalar multiplication of a point by an integer.
 * Compiled to 256-iteration double-and-add using Jacobian coordinates.
 */
export function ecMul(_p: Point, _k: bigint): Point {
  return compilerStub('ecMul');
}

/**
 * Scalar multiplication of the generator point G by an integer.
 * Equivalent to `ecMul(EC_G, k)` but the generator is hardcoded.
 */
export function ecMulGen(_k: bigint): Point {
  return compilerStub('ecMulGen');
}

/**
 * Negate an elliptic curve point: returns (x, p - y).
 */
export function ecNegate(_p: Point): Point {
  return compilerStub('ecNegate');
}

/**
 * Check if a point lies on the secp256k1 curve: y² ≡ x³ + 7 (mod p).
 */
export function ecOnCurve(_p: Point): boolean {
  return compilerStub('ecOnCurve');
}

/**
 * Modular reduction: `((value % mod) + mod) % mod`.
 * Ensures non-negative result for use with EC group order.
 */
export function ecModReduce(_value: bigint, _mod: bigint): bigint {
  return compilerStub('ecModReduce');
}

/**
 * Encode a point as a 33-byte compressed public key (02/03 prefix + x).
 */
export function ecEncodeCompressed(_p: Point): ByteString {
  return compilerStub('ecEncodeCompressed');
}

/**
 * Construct a Point from two bigint coordinates (x, y).
 * Each coordinate is encoded as a 32-byte big-endian unsigned integer.
 */
export function ecMakePoint(_x: bigint, _y: bigint): Point {
  return compilerStub('ecMakePoint');
}

/**
 * Extract the x-coordinate from a Point as a bigint.
 */
export function ecPointX(_p: Point): bigint {
  return compilerStub('ecPointX');
}

/**
 * Extract the y-coordinate from a Point as a bigint.
 */
export function ecPointY(_p: Point): bigint {
  return compilerStub('ecPointY');
}

// ---------------------------------------------------------------------------
// Baby Bear field arithmetic (p = 2^31 - 2^27 + 1 = 2013265921)
// ---------------------------------------------------------------------------

/**
 * Baby Bear field addition: (a + b) mod p.
 * Used by SP1 STARK FRI verification.
 * Compiles to: `OP_ADD <p> OP_MOD`
 */
export function bbFieldAdd(_a: bigint, _b: bigint): bigint {
  return compilerStub('bbFieldAdd');
}

/**
 * Baby Bear field subtraction: (a - b + p) mod p.
 * Used by SP1 STARK FRI verification.
 */
export function bbFieldSub(_a: bigint, _b: bigint): bigint {
  return compilerStub('bbFieldSub');
}

/**
 * Baby Bear field multiplication: (a * b) mod p.
 * Used by SP1 STARK FRI verification.
 * Products are at most ~2^62, within BSV script number limits.
 */
export function bbFieldMul(_a: bigint, _b: bigint): bigint {
  return compilerStub('bbFieldMul');
}

/**
 * Baby Bear field multiplicative inverse: a^(p-2) mod p.
 * Uses Fermat's little theorem. ~30 squarings + ~27 multiplies.
 * Used by SP1 STARK FRI verification.
 */
export function bbFieldInv(_a: bigint): bigint {
  return compilerStub('bbFieldInv');
}

// ---------------------------------------------------------------------------
// Baby Bear quartic extension field (degree-4 over BabyBear, W = 11)
// ---------------------------------------------------------------------------
// The extension is F[X]/(X^4 - 11) where F is the Baby Bear base field.
// Elements are (a0, a1, a2, a3) with each component a base field element.
// SP1/Plonky3 uses this for FRI challenge sampling and DEEP quotient evaluation.
//
// Extension addition/subtraction are component-wise — use bbFieldAdd/bbFieldSub.
// These builtins handle multiplication and inverse which involve cross-terms.
// Each function returns one component of the result (index 0-3).
// ---------------------------------------------------------------------------

/**
 * Component 0 of Baby Bear quartic extension multiplication.
 * r0 = a0*b0 + 11*(a1*b3 + a2*b2 + a3*b1) mod p
 */
export function bbExt4Mul0(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint, _b0: bigint, _b1: bigint, _b2: bigint, _b3: bigint): bigint {
  return compilerStub('bbExt4Mul0');
}

/**
 * Component 1 of Baby Bear quartic extension multiplication.
 * r1 = a0*b1 + a1*b0 + 11*(a2*b3 + a3*b2) mod p
 */
export function bbExt4Mul1(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint, _b0: bigint, _b1: bigint, _b2: bigint, _b3: bigint): bigint {
  return compilerStub('bbExt4Mul1');
}

/**
 * Component 2 of Baby Bear quartic extension multiplication.
 * r2 = a0*b2 + a1*b1 + a2*b0 + 11*(a3*b3) mod p
 */
export function bbExt4Mul2(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint, _b0: bigint, _b1: bigint, _b2: bigint, _b3: bigint): bigint {
  return compilerStub('bbExt4Mul2');
}

/**
 * Component 3 of Baby Bear quartic extension multiplication.
 * r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 mod p
 */
export function bbExt4Mul3(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint, _b0: bigint, _b1: bigint, _b2: bigint, _b3: bigint): bigint {
  return compilerStub('bbExt4Mul3');
}

/**
 * Component 0 of Baby Bear quartic extension inverse.
 * Uses tower-of-quadratic-extensions algorithm.
 */
export function bbExt4Inv0(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint): bigint {
  return compilerStub('bbExt4Inv0');
}

/**
 * Component 1 of Baby Bear quartic extension inverse.
 */
export function bbExt4Inv1(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint): bigint {
  return compilerStub('bbExt4Inv1');
}

/**
 * Component 2 of Baby Bear quartic extension inverse.
 */
export function bbExt4Inv2(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint): bigint {
  return compilerStub('bbExt4Inv2');
}

/**
 * Component 3 of Baby Bear quartic extension inverse.
 */
export function bbExt4Inv3(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint): bigint {
  return compilerStub('bbExt4Inv3');
}

// ---------------------------------------------------------------------------
// KoalaBear field arithmetic (p = 2^31 - 2^24 + 1 = 2,130,706,433)
// ---------------------------------------------------------------------------
// The KoalaBear prime field, used by SP1 v6 STARK proofs (StackedBasefold).
// Identical structure to BabyBear but different prime (0x7f000001 vs 0x78000001).
// Extension field uses irreducible x^4 - 3 (W=3, vs BabyBear's W=11).
// ---------------------------------------------------------------------------

/**
 * KoalaBear field addition: (a + b) mod p.
 * Used by SP1 v6 StackedBasefold verification.
 * Compiles to: `OP_ADD <p> OP_MOD`
 */
export function kbFieldAdd(_a: bigint, _b: bigint): bigint {
  return compilerStub('kbFieldAdd');
}

/**
 * KoalaBear field subtraction: (a - b + p) mod p.
 * Used by SP1 v6 StackedBasefold verification.
 */
export function kbFieldSub(_a: bigint, _b: bigint): bigint {
  return compilerStub('kbFieldSub');
}

/**
 * KoalaBear field multiplication: (a * b) mod p.
 * Used by SP1 v6 StackedBasefold verification.
 * Products are at most ~2^62, within BSV script number limits.
 */
export function kbFieldMul(_a: bigint, _b: bigint): bigint {
  return compilerStub('kbFieldMul');
}

/**
 * KoalaBear field multiplicative inverse: a^(p-2) mod p.
 * Uses Fermat's little theorem. ~30 squarings + ~29 multiplies.
 * Used by SP1 v6 StackedBasefold verification.
 */
export function kbFieldInv(_a: bigint): bigint {
  return compilerStub('kbFieldInv');
}

// ---------------------------------------------------------------------------
// KoalaBear quartic extension field (degree-4 over KoalaBear, W = 3)
// ---------------------------------------------------------------------------
// The extension is F[X]/(X^4 - 3) where F is the KoalaBear base field.
// Elements are (a0, a1, a2, a3) with each component a base field element.
// SP1 v6 uses this for Basefold challenge sampling and evaluation.
//
// Extension addition/subtraction are component-wise — use kbFieldAdd/kbFieldSub.
// These builtins handle multiplication and inverse which involve cross-terms.
// Each function returns one component of the result (index 0-3).
// ---------------------------------------------------------------------------

/**
 * Component 0 of KoalaBear quartic extension multiplication.
 * r0 = a0*b0 + 3*(a1*b3 + a2*b2 + a3*b1) mod p
 */
export function kbExt4Mul0(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint, _b0: bigint, _b1: bigint, _b2: bigint, _b3: bigint): bigint {
  return compilerStub('kbExt4Mul0');
}

/**
 * Component 1 of KoalaBear quartic extension multiplication.
 * r1 = a0*b1 + a1*b0 + 3*(a2*b3 + a3*b2) mod p
 */
export function kbExt4Mul1(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint, _b0: bigint, _b1: bigint, _b2: bigint, _b3: bigint): bigint {
  return compilerStub('kbExt4Mul1');
}

/**
 * Component 2 of KoalaBear quartic extension multiplication.
 * r2 = a0*b2 + a1*b1 + a2*b0 + 3*(a3*b3) mod p
 */
export function kbExt4Mul2(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint, _b0: bigint, _b1: bigint, _b2: bigint, _b3: bigint): bigint {
  return compilerStub('kbExt4Mul2');
}

/**
 * Component 3 of KoalaBear quartic extension multiplication.
 * r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 mod p
 */
export function kbExt4Mul3(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint, _b0: bigint, _b1: bigint, _b2: bigint, _b3: bigint): bigint {
  return compilerStub('kbExt4Mul3');
}

/**
 * Component 0 of KoalaBear quartic extension inverse.
 * Uses tower-of-quadratic-extensions algorithm.
 */
export function kbExt4Inv0(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint): bigint {
  return compilerStub('kbExt4Inv0');
}

/**
 * Component 1 of KoalaBear quartic extension inverse.
 */
export function kbExt4Inv1(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint): bigint {
  return compilerStub('kbExt4Inv1');
}

/**
 * Component 2 of KoalaBear quartic extension inverse.
 */
export function kbExt4Inv2(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint): bigint {
  return compilerStub('kbExt4Inv2');
}

/**
 * Component 3 of KoalaBear quartic extension inverse.
 */
export function kbExt4Inv3(_a0: bigint, _a1: bigint, _a2: bigint, _a3: bigint): bigint {
  return compilerStub('kbExt4Inv3');
}

// ---------------------------------------------------------------------------
// BN254 field arithmetic (p = 21888242871839275222246405745257275088696311157297823662689037894645226208583)
// ---------------------------------------------------------------------------
// The BN254 (alt_bn128) prime field, used for Groth16 SNARK verification.
// 254-bit prime, requires multi-limb script arithmetic.
// ---------------------------------------------------------------------------

/**
 * BN254 field addition: (a + b) mod p.
 */
export function bn254FieldAdd(_a: bigint, _b: bigint): bigint {
  return compilerStub('bn254FieldAdd');
}

/**
 * BN254 field subtraction: (a - b + p) mod p.
 */
export function bn254FieldSub(_a: bigint, _b: bigint): bigint {
  return compilerStub('bn254FieldSub');
}

/**
 * BN254 field multiplication: (a * b) mod p.
 */
export function bn254FieldMul(_a: bigint, _b: bigint): bigint {
  return compilerStub('bn254FieldMul');
}

/**
 * BN254 field multiplicative inverse: a^(p-2) mod p.
 */
export function bn254FieldInv(_a: bigint): bigint {
  return compilerStub('bn254FieldInv');
}

/**
 * BN254 field negation: (p - a) mod p.
 */
export function bn254FieldNeg(_a: bigint): bigint {
  return compilerStub('bn254FieldNeg');
}

// ---------------------------------------------------------------------------
// BN254 G1 curve operations (y^2 = x^3 + 3)
// ---------------------------------------------------------------------------

/**
 * BN254 G1 point addition.
 */
export function bn254G1Add(_p1: Point, _p2: Point): Point {
  return compilerStub('bn254G1Add');
}

/**
 * BN254 G1 scalar multiplication.
 */
export function bn254G1ScalarMul(_p: Point, _s: bigint): Point {
  return compilerStub('bn254G1ScalarMul');
}

/**
 * BN254 G1 point negation: (x, p-y).
 */
export function bn254G1Negate(_p: Point): Point {
  return compilerStub('bn254G1Negate');
}

/**
 * BN254 G1 on-curve check: y^2 == x^3 + 3 mod p.
 */
export function bn254G1OnCurve(_p: Point): boolean {
  return compilerStub('bn254G1OnCurve') as unknown as boolean;
}

// ---------------------------------------------------------------------------
// Merkle proof verification
// ---------------------------------------------------------------------------

/**
 * Compute Merkle root from a leaf and authentication path using SHA-256.
 *
 * @param _leaf  - 32-byte leaf hash
 * @param _proof - Concatenated 32-byte sibling hashes (depth * 32 bytes)
 * @param _index - Leaf position (determines left/right at each level)
 * @param _depth - Number of levels (MUST be a compile-time constant)
 * @returns The computed 32-byte Merkle root
 */
export function merkleRootSha256(
  _leaf: ByteString,
  _proof: ByteString,
  _index: bigint,
  _depth: bigint,
): ByteString {
  return compilerStub('merkleRootSha256');
}

/**
 * Compute Merkle root from a leaf and authentication path using Hash256 (double SHA-256).
 * Same as merkleRootSha256 but uses OP_HASH256 instead of OP_SHA256.
 * Standard Bitcoin Merkle tree format.
 *
 * @param _leaf  - 32-byte leaf hash
 * @param _proof - Concatenated 32-byte sibling hashes (depth * 32 bytes)
 * @param _index - Leaf position (determines left/right at each level)
 * @param _depth - Number of levels (MUST be a compile-time constant)
 * @returns The computed 32-byte Merkle root
 */
export function merkleRootHash256(
  _leaf: ByteString,
  _proof: ByteString,
  _index: bigint,
  _depth: bigint,
): ByteString {
  return compilerStub('merkleRootHash256');
}
