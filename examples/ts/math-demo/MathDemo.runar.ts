import {
  StatefulSmartContract,
  assert,
  safediv,
  percentOf,
  clamp,
  sign,
  pow,
  sqrt,
  gcd,
  mulDiv,
  log2,
} from 'runar-lang';

/**
 * MathDemo — A stateful contract demonstrating every built-in math function
 * available in Rúnar.
 *
 * Bitcoin Script has limited native arithmetic (ADD, SUB, MUL, DIV, MOD).
 * Rúnar provides higher-level math functions that compile into sequences of
 * these primitives, enabling complex financial calculations on-chain.
 *
 * Each public method applies one math operation to the contract's stored
 * `value`, showing how these functions compile to pure Bitcoin Script.
 * All operations use integer math — no floating point.
 *
 * This contract is intentionally minimal: no signature checks are performed,
 * so any caller can invoke any method. In production, you would combine these
 * math operations with authentication logic.
 */
class MathDemo extends StatefulSmartContract {
  value: bigint;

  constructor(value: bigint) {
    super(value);
    this.value = value;
  }

  /**
   * Safe division — divides the stored value by `divisor`, asserting that
   * `divisor` is non-zero. The transaction fails if divisor is 0.
   *
   * Use cases: splitting payments, computing averages.
   */
  public divideBy(divisor: bigint) {
    this.value = safediv(this.value, divisor);
  }

  /**
   * Withdraw with a fee calculated in basis points (1 bps = 0.01%).
   * `percentOf(amount, feeBps)` computes `amount * feeBps / 10000`.
   * Asserts that the total (amount + fee) does not exceed the stored value.
   *
   * Use cases: fee calculation, royalties, commission deductions.
   */
  public withdrawWithFee(amount: bigint, feeBps: bigint) {
    const fee = percentOf(amount, feeBps);
    const total = amount + fee;
    assert(total <= this.value);
    this.value = this.value - total;
  }

  /**
   * Constrains the stored value to the range [lo, hi].
   * If value < lo, it becomes lo. If value > hi, it becomes hi.
   *
   * Use cases: enforcing min/max limits on bids, prices, or balances.
   */
  public clampValue(lo: bigint, hi: bigint) {
    this.value = clamp(this.value, lo, hi);
  }

  /**
   * Replaces the stored value with its sign: -1, 0, or 1.
   *
   * Use cases: direction detection, comparison results, branch selection.
   */
  public normalize() {
    this.value = sign(this.value);
  }

  /**
   * Raises the stored value to the power `exp` (integer exponentiation).
   *
   * Use cases: compound interest, polynomial evaluation.
   */
  public exponentiate(exp: bigint) {
    this.value = pow(this.value, exp);
  }

  /**
   * Replaces the stored value with its integer square root (floor).
   *
   * Use cases: geometric mean, distance calculations.
   */
  public squareRoot() {
    this.value = sqrt(this.value);
  }

  /**
   * Replaces the stored value with gcd(value, other) — the greatest
   * common divisor.
   *
   * Use cases: fraction simplification, coprimality checks.
   */
  public reduceGcd(other: bigint) {
    this.value = gcd(this.value, other);
  }

  /**
   * Computes `(value * numerator) / denominator` with intermediate precision
   * to avoid overflow. Replaces the stored value with the result.
   *
   * Use cases: currency conversion, proportional allocation, token swaps.
   */
  public scaleByRatio(numerator: bigint, denominator: bigint) {
    this.value = mulDiv(this.value, numerator, denominator);
  }

  /**
   * Replaces the stored value with floor(log2(value)) — the floor of the
   * base-2 logarithm.
   *
   * Use cases: bit-length calculation, binary search depth.
   */
  public computeLog2() {
    this.value = log2(this.value);
  }
}
