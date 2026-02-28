// ---------------------------------------------------------------------------
// tsop-lang — TSOP smart contract language: base class, types, and builtins
// ---------------------------------------------------------------------------
// This is the contract author's import library for writing Bitcoin SV smart
// contracts in TypeScript.  Contracts extend `SmartContract`, use the
// branded domain types, and call the built-in functions — all of which the
// TSOP compiler maps to Bitcoin Script opcodes.
//
// Design philosophy: No decorators.  TypeScript's own keywords (public,
// private, readonly, abstract) provide all the expressiveness needed.
// ---------------------------------------------------------------------------

import type { ByteString, Addr } from './types.js';

// ---------------------------------------------------------------------------
// Re-exports — types
// ---------------------------------------------------------------------------
// Names that exist as both a type alias AND a value-level constructor function
// (PubKey, Sig, etc.) must be re-exported in a single statement to satisfy
// isolatedModules.
// ---------------------------------------------------------------------------

export {
  // Value constructors (which also serve as the type names via declaration
  // merging at the consumer's import site):
  toByteString,
  PubKey,
  Sig,
  Ripemd160,
  Sha256,
  Addr,
  SigHashPreimage,
  OpCodeType,
  SigHash,
  // Pure types (no runtime value):
  type ByteString,
  type SigHashType,
  type RabinSig,
  type RabinPubKey,
  type FixedArray,
} from './types.js';

// ---------------------------------------------------------------------------
// Re-exports — builtins
// ---------------------------------------------------------------------------

export {
  // Crypto
  sha256,
  ripemd160,
  hash160,
  hash256,
  checkSig,
  checkMultiSig,
  // Byte operations
  len,
  cat,
  substr,
  left,
  right,
  split,
  reverseBytes,
  // Conversion
  num2bin,
  bin2num,
  int2str,
  // Assertion
  assert,
  // Math
  abs,
  min,
  max,
  within,
  // Rabin (also re-exported from oracle subpath)
  verifyRabinSig,
} from './builtins.js';

// ---------------------------------------------------------------------------
// Re-exports — preimage
// ---------------------------------------------------------------------------

export {
  checkPreimage,
  extractVersion,
  extractHashPrevouts,
  extractHashSequence,
  extractOutpoint,
  extractInputIndex,
  extractScriptCode,
  extractAmount,
  extractSequence,
  extractOutputHash,
  extractOutputs,
  extractLocktime,
  extractSigHashType,
} from './preimage.js';

// ---------------------------------------------------------------------------
// SmartContract base class
// ---------------------------------------------------------------------------

/**
 * Abstract base class for all TSOP smart contracts.
 *
 * Contract authors extend this class and define public methods that serve as
 * spending paths.  The compiler analyses the class and emits a Bitcoin Script
 * locking script.
 *
 * ```ts
 * import { SmartContract, assert, checkSig } from 'tsop-lang';
 * import type { PubKey, Sig } from 'tsop-lang';
 *
 * class P2PKH extends SmartContract {
 *   readonly pubKeyHash: Addr;
 *
 *   constructor(pubKeyHash: Addr) {
 *     super(pubKeyHash);
 *     this.pubKeyHash = pubKeyHash;
 *   }
 *
 *   public unlock(sig: Sig, pubkey: PubKey) {
 *     assert(hash160(pubkey) === this.pubKeyHash);
 *     assert(checkSig(sig, pubkey));
 *   }
 * }
 * ```
 */
export abstract class SmartContract {
  /**
   * Constructor arguments are the contract's compile-time parameters.
   * They become embedded in the locking script.
   *
   * Subclasses MUST call `super(...)` forwarding all constructor args so
   * the compiler can track them.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(..._args: unknown[]) {
    // Intentionally empty.  The compiler extracts constructor parameters
    // from the TypeScript AST — no runtime bookkeeping is needed.
  }

  // -----------------------------------------------------------------------
  // Compiler intrinsics
  // -----------------------------------------------------------------------

  /**
   * Generate the locking script for the current contract state.
   *
   * Used in stateful contracts to propagate state: the contract constructs
   * a new output whose script is `this.getStateScript()` with updated
   * property values, then enforces that the spending transaction contains
   * that output.
   *
   * ```ts
   * // Inside a public method:
   * this.counter++;
   * const output = num2bin(amount, 8n) + this.getStateScript();
   * assert(hash256(output) === extractOutputHash(preimage));
   * ```
   *
   * Compiles to: an inline reconstruction of the locking script with the
   * updated state values substituted.
   */
  protected getStateScript(): ByteString {
    throw new Error(
      'SmartContract.getStateScript() cannot be called at runtime — compile this contract.',
    );
  }

  /**
   * Build a standard P2PKH output script for the given address.
   *
   * Equivalent to:
   *   OP_DUP OP_HASH160 <addr> OP_EQUALVERIFY OP_CHECKSIG
   *
   * Useful for constructing expected outputs in contracts that enforce
   * payment to a specific address.
   *
   * @param addr - A 20-byte address (Hash160 of a pubkey).
   * @returns The serialized 25-byte P2PKH locking script.
   */
  protected buildP2PKH(_addr: Addr): ByteString {
    throw new Error(
      'SmartContract.buildP2PKH() cannot be called at runtime — compile this contract.',
    );
  }
}
