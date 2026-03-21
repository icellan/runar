// ---------------------------------------------------------------------------
// runar-lang — Rúnar smart contract language: base class, types, and builtins
// ---------------------------------------------------------------------------
// This is the contract author's import library for writing Bitcoin SV smart
// contracts in TypeScript.  Contracts extend `SmartContract`, use the
// branded domain types, and call the built-in functions — all of which the
// Rúnar compiler maps to Bitcoin Script opcodes.
//
// Design philosophy: No decorators.  TypeScript's own keywords (public,
// private, readonly, abstract) provide all the expressiveness needed.
// ---------------------------------------------------------------------------

import type { ByteString, Addr, SigHashPreimage as SigHashPreimageType } from './types.js';

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
  Point,
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
  safediv,
  safemod,
  clamp,
  sign,
  pow,
  mulDiv,
  percentOf,
  sqrt,
  gcd,
  divmod,
  log2,
  bool,
  // Rabin (also re-exported from oracle subpath)
  verifyRabinSig,
  // Post-quantum (hash-based)
  verifyWOTS,
  verifySLHDSA_SHA2_128s,
  verifySLHDSA_SHA2_128f,
  verifySLHDSA_SHA2_192s,
  verifySLHDSA_SHA2_192f,
  verifySLHDSA_SHA2_256s,
  verifySLHDSA_SHA2_256f,
  // SHA-256 partial
  sha256Compress,
  sha256Finalize,
  // BLAKE3
  blake3Compress,
  blake3Hash,
  // Elliptic curve operations
  ecAdd,
  ecMul,
  ecMulGen,
  ecNegate,
  ecOnCurve,
  ecModReduce,
  ecEncodeCompressed,
  ecMakePoint,
  ecPointX,
  ecPointY,
} from './builtins.js';

// ---------------------------------------------------------------------------
// Re-exports — elliptic curve constants
// ---------------------------------------------------------------------------

export { EC_P, EC_N, EC_G } from './ec.js';

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
 * Abstract base class for all Rúnar smart contracts.
 *
 * Contract authors extend this class and define public methods that serve as
 * spending paths.  The compiler analyses the class and emits a Bitcoin Script
 * locking script.
 *
 * ```ts
 * import { SmartContract, assert, checkSig } from 'runar-lang';
 * import type { PubKey, Sig } from 'runar-lang';
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

// ---------------------------------------------------------------------------
// StatefulSmartContract base class
// ---------------------------------------------------------------------------

/**
 * Base class for stateful Rúnar smart contracts.
 *
 * Extends {@link SmartContract} with automatic transaction preimage
 * verification and state continuation. The compiler injects two things
 * into every public method:
 *
 * 1. **Preimage check** — `assert(checkPreimage(txPreimage))` at method
 *    entry, verifying the sighash preimage is valid for the current
 *    spending transaction.
 *
 * 2. **State continuation** — for methods that modify mutable (non-readonly)
 *    properties, `assert(hash256(this.getStateScript()) ===
 *    extractOutputHash(txPreimage))` at method exit, ensuring the
 *    spending transaction carries the updated state forward.
 *
 * Contract methods can access preimage fields via the implicit
 * `this.txPreimage` property and the `extract*` helpers:
 *
 * ```ts
 * import { StatefulSmartContract, assert, extractLocktime } from 'runar-lang';
 * import type { PubKey, Sig } from 'runar-lang';
 *
 * class Counter extends StatefulSmartContract {
 *   count: bigint;
 *
 *   constructor(count: bigint) {
 *     super(count);
 *     this.count = count;
 *   }
 *
 *   public increment() {
 *     this.count++;
 *   }
 * }
 * ```
 */
export abstract class StatefulSmartContract extends SmartContract {
  /**
   * The sighash preimage for the current spending transaction.
   *
   * Automatically verified by the compiler at method entry via
   * `checkPreimage()`. Use the `extract*` helpers to read fields:
   *
   * ```ts
   * assert(extractLocktime(this.txPreimage) >= this.deadline);
   * ```
   */
  protected readonly txPreimage!: SigHashPreimageType;

  /**
   * Register a transaction output with custom state values.
   *
   * Each call adds one output to the transaction. At method exit, the
   * compiler verifies that all registered outputs match the transaction's
   * `hashOutputs` field.
   *
   * Arguments after `satoshis` correspond to the mutable (non-readonly)
   * properties **in declaration order**.
   *
   * ```ts
   * // For a contract with mutable props [owner: PubKey, balance: bigint]:
   * this.addOutput(satoshis, recipientPubKey, amount);
   * this.addOutput(satoshis, this.owner, this.balance - amount);
   * ```
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  protected addOutput(_satoshis: bigint, ..._stateValues: unknown[]): void {
    throw new Error(
      'StatefulSmartContract.addOutput() cannot be called at runtime — compile this contract.',
    );
  }

  /**
   * Adds a raw output with caller-specified script bytes.
   * The script is used as-is without wrapping in the contract's codePart.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  protected addRawOutput(_satoshis: bigint, _scriptBytes: ByteString): void {
    throw new Error(
      'StatefulSmartContract.addRawOutput() cannot be called at runtime — compile this contract.',
    );
  }
}
