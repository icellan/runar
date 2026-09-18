import { SmartContract, assert, num2bin, bin2num } from 'runar-lang';

/**
 * R-RustBigint — the reference half of the Rust `BigintBig` spelling pair.
 *
 * This is `RustBigintBigSpellings.runar.rs` written with `bigint` and the
 * unsuffixed encoders. The two files must compile to the SAME script hex, in
 * every tier, and `subtype-parity.test.ts` asserts exactly that.
 *
 * Why the pair and not just the `.runar.rs` file. The corpus in this directory
 * already requires every tier to agree on the bytes for a given fixture, which
 * catches a tier that does not know `BigintBig` or `num2bin_big`. It does NOT
 * catch seven tiers agreeing on a WRONG rewrite — `num2bin_big` lowered to
 * `bin2num`, say, which is a plausible copy-paste and which every tier would
 * then emit identically. Only comparison against the unsuffixed spelling
 * distinguishes "they agree" from "they are right".
 *
 * `BigintBig` is a different Rust RUNTIME type, not a different Script
 * operation: `Bigint` is `i64` in `packages/runar-rs` and refuses what it
 * cannot represent, `BigintBig` is `num_bigint::BigInt` and does not. Both are
 * the `bigint` primitive once parsed, so the emitted bytes must be identical
 * and reaching for the wide spelling must cost nothing on-chain.
 *
 * Keep the two files in lockstep: same contract shape, same property, same
 * method names, same parameter names, same binding names, same order. The claim
 * is byte equality, and any of those changes it.
 */
class RustBigintBigSpellingsRef extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public checkWideEncoders(a: bigint) {
    const encoded = num2bin(a, 8n);
    assert(bin2num(encoded) === this.expected);
  }

  public checkArithmetic(a: bigint, b: bigint) {
    const sum: bigint = a + b;
    const diff: bigint = a - b;
    const total: bigint = sum + diff;
    assert(total === this.expected);
  }

  public checkComparisons(a: bigint, b: bigint) {
    assert(a < b);
    assert(a <= b);
    assert(b > a);
    assert(b >= a);
    assert(a !== b);
    assert(a === a);
  }
}
