// FunctionPatterns demonstrates every way functions and methods can be
// used inside a Rúnar TypeScript contract.
//
// Rúnar contracts support four categories of callable code:
//
//   1. Public methods      — declared with the `public` keyword.
//                            These are the spending entry points that
//                            appear in the compiled Bitcoin Script.
//
//   2. Private methods     — declared with `private` (or no modifier).
//                            These can access contract state via `this`
//                            and are inlined by the compiler at call sites.
//                            Private methods may return a value.
//
//   3. Built-in functions  — imported from 'runar-lang' (e.g. assert,
//                            checkSig, safediv, percentOf, clamp).
//                            These map directly to Bitcoin Script opcodes.
//
// Note: TypeScript contracts cannot define standalone functions outside
// the class. All helper logic must be private methods on the class.

import {
  StatefulSmartContract,
  assert,
  checkSig,
  percentOf,
  mulDiv,
  clamp,
  safemod,
} from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class FunctionPatterns extends StatefulSmartContract {
  readonly owner: PubKey;  // immutable: contract creator
  balance: bigint;         // stateful: current balance

  constructor(owner: PubKey, balance: bigint) {
    super(owner, balance);
    this.owner = owner;
    this.balance = balance;
  }

  // -----------------------------------------------------------------------
  // 1. Public methods — spending entry points
  // -----------------------------------------------------------------------
  // Public methods become separate OP_IF branches in the compiled locking
  // script. The spending transaction selects which method to execute via a
  // method index pushed in the scriptSig.
  //
  // Public methods must not return a value.

  /** Deposit adds funds. Calls a private method and a built-in. */
  public deposit(sig: Sig, amount: bigint) {
    // Private method: shared signature check
    this.requireOwner(sig);

    // Built-in: assertion
    assert(amount > 0n);

    // Update state
    this.balance = this.balance + amount;
  }

  /**
   * Withdraw removes funds after applying a fee.
   * Demonstrates chaining a private method that returns a value.
   */
  public withdraw(sig: Sig, amount: bigint, feeBps: bigint) {
    this.requireOwner(sig);
    assert(amount > 0n);

    // Private method with return value
    const fee = this.computeFee(amount, feeBps);
    const total = amount + fee;

    assert(total <= this.balance);
    this.balance = this.balance - total;
  }

  /**
   * Scale multiplies the balance by a rational number.
   * Demonstrates calling a private method that wraps a built-in.
   */
  public scale(sig: Sig, numerator: bigint, denominator: bigint) {
    this.requireOwner(sig);
    this.balance = this.scaleValue(this.balance, numerator, denominator);
  }

  /**
   * Normalize clamps the balance to a range and rounds down.
   * Demonstrates composing multiple private helper methods.
   */
  public normalize(sig: Sig, lo: bigint, hi: bigint, step: bigint) {
    this.requireOwner(sig);
    const clamped = this.clampValue(this.balance, lo, hi);
    this.balance = this.roundDown(clamped, step);
  }

  // -----------------------------------------------------------------------
  // 2. Private methods — inlined helpers
  // -----------------------------------------------------------------------
  // Private methods can read/write contract state via `this` and may
  // return a value. The compiler inlines them at each call site — they
  // do not become separate script functions.

  /** Verify the caller is the contract owner. Shared by all public methods. */
  private requireOwner(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }

  /** Compute a fee in basis points. Returns the fee amount. */
  private computeFee(amount: bigint, feeBps: bigint): bigint {
    return percentOf(amount, feeBps);
  }

  /** Multiply a value by a fraction using mulDiv for precision. */
  private scaleValue(value: bigint, numerator: bigint, denominator: bigint): bigint {
    return mulDiv(value, numerator, denominator);
  }

  /** Clamp a value to [lo, hi]. */
  private clampValue(value: bigint, lo: bigint, hi: bigint): bigint {
    return clamp(value, lo, hi);
  }

  /** Round down to the nearest multiple of step. */
  private roundDown(value: bigint, step: bigint): bigint {
    const remainder = safemod(value, step);
    return value - remainder;
  }
}
