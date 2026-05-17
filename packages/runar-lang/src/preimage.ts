// ---------------------------------------------------------------------------
// runar-lang/preimage.ts — SigHash preimage parsing utilities
// ---------------------------------------------------------------------------
// Bitcoin SV's sighash preimage is the serialized data that gets double-
// SHA-256'd to produce the digest that OP_CHECKSIG verifies.  These helper
// functions extract individual fields from the preimage so contract authors
// can enforce constraints on the transaction spending the UTXO.
//
// Preimage layout (BIP-143 / Bitcoin SV):
//   Offset  Bytes  Field
//   ──────  ─────  ─────────────────────────────
//        0      4  nVersion
//        4     32  hashPrevouts
//       36     32  hashSequence
//       68     36  outpoint (txid 32 + vout 4)
//      104   var   scriptCode (varint-prefixed)
//      var      8  amount (satoshis, LE int64)
//      var      4  nSequence
//      var     32  hashOutputs
//      var      4  nLocktime
//      var      4  sighashType
// ---------------------------------------------------------------------------

import type { ByteString, Sha256, SigHashPreimage } from './types.js';

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

function compilerStub(name: string): never {
  throw new Error(
    `${name}() cannot be called at runtime — compile this contract with the Rúnar compiler.`,
  );
}

// ---------------------------------------------------------------------------
// Preimage verification
// ---------------------------------------------------------------------------

/**
 * Verify that `txPreimage` is the valid sighash preimage for the current
 * transaction input.  The compiler emits the necessary OP_CHECKSIG /
 * OP_HASH256 sequence to verify this on-chain.
 *
 * @returns `true` if the preimage is valid for the executing input.
 */
export function checkPreimage(_txPreimage: SigHashPreimage): boolean {
  return compilerStub('checkPreimage');
}

// ---------------------------------------------------------------------------
// Field extractors
// ---------------------------------------------------------------------------

/**
 * Extract the 4-byte transaction version (nVersion) from the preimage.
 * Preimage bytes [0..4).
 */
export function extractVersion(_txPreimage: SigHashPreimage): bigint {
  return compilerStub('extractVersion');
}

/**
 * Extract the 32-byte hashPrevouts from the preimage.
 * Preimage bytes [4..36).
 */
export function extractHashPrevouts(_txPreimage: SigHashPreimage): Sha256 {
  return compilerStub('extractHashPrevouts');
}

/**
 * Extract the 32-byte hashSequence from the preimage.
 * Preimage bytes [36..68).
 */
export function extractHashSequence(_txPreimage: SigHashPreimage): Sha256 {
  return compilerStub('extractHashSequence');
}

/**
 * Extract the 36-byte outpoint (prev txid + vout index) being spent.
 * Preimage bytes [68..104).
 */
export function extractOutpoint(_txPreimage: SigHashPreimage): ByteString {
  return compilerStub('extractOutpoint');
}

/**
 * Extract the input index (4-byte little-endian within the outpoint).
 * This is the vout index of the UTXO being spent: preimage bytes [100..104).
 */
export function extractInputIndex(_txPreimage: SigHashPreimage): bigint {
  return compilerStub('extractInputIndex');
}

/**
 * Extract the scriptCode field from the preimage.  The scriptCode starts at
 * byte 104 with a varint length prefix followed by the script bytes.
 *
 * The compiler resolves the variable-length offset at compile time.
 */
export function extractScriptCode(_txPreimage: SigHashPreimage): ByteString {
  return compilerStub('extractScriptCode');
}

/**
 * Extract the 8-byte input amount (satoshis, little-endian int64).
 * Located immediately after the scriptCode field.
 */
export function extractAmount(_txPreimage: SigHashPreimage): bigint {
  return compilerStub('extractAmount');
}

/**
 * Extract the 4-byte nSequence of the current input.
 * Located immediately after the amount field.
 */
export function extractSequence(_txPreimage: SigHashPreimage): bigint {
  return compilerStub('extractSequence');
}

/**
 * Extract the 32-byte hashOutputs from the preimage.
 * Located after nSequence.
 */
export function extractOutputHash(_txPreimage: SigHashPreimage): Sha256 {
  return compilerStub('extractOutputHash');
}

/**
 * Extract the full serialized outputs referenced by hashOutputs.
 *
 * NOTE: This is an alias that returns the hashOutputs digest.  To enforce
 * constraints on individual outputs the contract should reconstruct the
 * expected outputs and compare the hash.
 */
export function extractOutputs(_txPreimage: SigHashPreimage): Sha256 {
  return compilerStub('extractOutputs');
}

/**
 * Extract the 4-byte nLocktime from the preimage.
 * Located after hashOutputs.
 */
export function extractLocktime(_txPreimage: SigHashPreimage): bigint {
  return compilerStub('extractLocktime');
}

/**
 * Extract the 4-byte sighash type from the end of the preimage.
 */
export function extractSigHashType(_txPreimage: SigHashPreimage): bigint {
  return compilerStub('extractSigHashType');
}

// ---------------------------------------------------------------------------
// Intent sub-covenant intrinsics (BSVM Phase 13)
// ---------------------------------------------------------------------------
// These are witness-bridge wrappers — pure source-level sugar that the
// compiler desugars into existing primitives plus auto-injected method
// parameters. The runtime stubs throw so test harnesses that mistakenly
// execute them off-chain surface a clear error. See
// docs/cross-covenant-pattern.md for the on-chain semantics.

/**
 * Extract the previous-output locking script for an arbitrary input of the
 * spending transaction. `inputIndex` MUST be a compile-time integer
 * literal. The compiler auto-injects a hidden method parameter
 * `_prevOutScript_<inputIndex>` (the unlocking script supplies the witness
 * bytes) and emits a hash assertion.
 *
 * Two forms:
 * - 2-arg: emits `hash256(witness) === expectedScriptHash`, pinning the
 *   full prev-output script byte-for-byte.
 * - 3-arg: emits `hash256(substr(witness, 0, prefixLen)) === expectedScriptPrefixHash`,
 *   pinning only the policy prefix and leaving the pushdata tail free
 *   to vary. `prefixLen` MUST also be a compile-time integer literal.
 *   Required for intent-template matching where each successor UTXO has
 *   a unique tail (BSVM Mode 3 permissionless step-in).
 */
export function extractPrevOutputScript(
  _inputIndex: bigint,
  _expectedScriptHash: ByteString,
  _prefixLen?: bigint,
): ByteString {
  return compilerStub('extractPrevOutputScript');
}

/**
 * Assert that the transaction's output at `outputIndex` is a standard
 * 34-byte P2PKH output paying exactly `amount` satoshis to `pubkeyHash`.
 * `outputIndex` MUST be a compile-time integer literal. Only valid in
 * StatefulSmartContract methods (relies on the auto-injected txPreimage).
 *
 * The compiler auto-injects `_serialisedOutputs` once per method,
 * emits a one-shot `hash256(_serialisedOutputs) === extractOutputHash(txPreimage)`
 * check, and per call asserts the 34-byte substring at offset
 * `outputIndex * 34` equals the expected P2PKH bytes.
 */
export function requireOutputP2PKH(
  _outputIndex: bigint,
  _pubkeyHash: ByteString,
  _amount: bigint,
): void {
  return compilerStub('requireOutputP2PKH');
}

/**
 * Shorthand for `extractLocktime(this.txPreimage)`. Only valid in
 * StatefulSmartContract methods. Pure source-level desugar — no new ANF
 * kind or stack codegen.
 */
export function currentBlockHeight(): bigint {
  return compilerStub('currentBlockHeight');
}
