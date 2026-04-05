import {
  SmartContract, assert,
  bbFieldAdd, bbFieldSub, bbFieldMul, bbFieldInv,
} from 'runar-lang';

/**
 * BabyBearDemo — Demonstrates Baby Bear prime field arithmetic.
 *
 * Baby Bear is the prime field used by SP1 STARK proofs (FRI verification).
 * Field prime: p = 2^31 - 2^27 + 1 = 2013265921
 *
 * Four operations:
 * - bbFieldAdd(a, b) — (a + b) mod p
 * - bbFieldSub(a, b) — (a - b + p) mod p
 * - bbFieldMul(a, b) — (a * b) mod p
 * - bbFieldInv(a) — a^(p-2) mod p (multiplicative inverse via Fermat)
 */
class BabyBearDemo extends SmartContract {
  constructor() {
    super();
  }

  /** Verify field addition. */
  public checkAdd(a: bigint, b: bigint, expected: bigint) {
    assert(bbFieldAdd(a, b) === expected);
  }

  /** Verify field subtraction. */
  public checkSub(a: bigint, b: bigint, expected: bigint) {
    assert(bbFieldSub(a, b) === expected);
  }

  /** Verify field multiplication. */
  public checkMul(a: bigint, b: bigint, expected: bigint) {
    assert(bbFieldMul(a, b) === expected);
  }

  /** Verify field inversion: a * inv(a) === 1. */
  public checkInv(a: bigint) {
    const inv = bbFieldInv(a);
    assert(bbFieldMul(a, inv) === 1n);
  }

  /** Verify subtraction is the inverse of addition: (a + b) - b === a. */
  public checkAddSubRoundtrip(a: bigint, b: bigint) {
    const sum = bbFieldAdd(a, b);
    const result = bbFieldSub(sum, b);
    assert(result === a);
  }

  /** Verify distributive law: a * (b + c) === a*b + a*c. */
  public checkDistributive(a: bigint, b: bigint, c: bigint) {
    const lhs = bbFieldMul(a, bbFieldAdd(b, c));
    const rhs = bbFieldAdd(bbFieldMul(a, b), bbFieldMul(a, c));
    assert(lhs === rhs);
  }
}
