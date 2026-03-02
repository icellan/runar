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

class MathDemo extends StatefulSmartContract {
  value: bigint;

  constructor(value: bigint) {
    super(value);
    this.value = value;
  }

  /** Safe division — asserts divisor is non-zero. */
  public divideBy(divisor: bigint) {
    this.value = safediv(this.value, divisor);
  }

  /** Withdraw with a fee in basis points (1 bps = 0.01%). */
  public withdrawWithFee(amount: bigint, feeBps: bigint) {
    const fee = percentOf(amount, feeBps);
    const total = amount + fee;
    assert(total <= this.value);
    this.value = this.value - total;
  }

  /** Clamp value to a range [lo, hi]. */
  public clampValue(lo: bigint, hi: bigint) {
    this.value = clamp(this.value, lo, hi);
  }

  /** Set value to its sign: -1, 0, or 1. */
  public normalize() {
    this.value = sign(this.value);
  }

  /** Raise value to an exponent. */
  public exponentiate(exp: bigint) {
    this.value = pow(this.value, exp);
  }

  /** Set value to its integer square root. */
  public squareRoot() {
    this.value = sqrt(this.value);
  }

  /** Set value to gcd(value, other). */
  public reduceGcd(other: bigint) {
    this.value = gcd(this.value, other);
  }

  /** Compute (value * numerator) / denominator without overflow concern. */
  public scaleByRatio(numerator: bigint, denominator: bigint) {
    this.value = mulDiv(this.value, numerator, denominator);
  }

  /** Set value to approximate floor(log2(value)). */
  public computeLog2() {
    this.value = log2(this.value);
  }
}
