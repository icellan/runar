import { SmartContract, assert, num2bin, bin2num } from 'runar-lang';

/**
 * R-Bigint — the reference half of the `BigintBig` operator-helper pair.
 *
 * This is GoBigintBigOperators.runar.go written with the operators themselves.
 * The two files must compile to the SAME script hex, in every tier, and
 * `subtype-parity.test.ts` asserts exactly that.
 *
 * Why the pair and not just the `.runar.go` file. The corpus in this directory
 * already requires every tier to agree on the bytes for a given fixture. That
 * catches a tier that does not know `runar.BigintBigLess`. It does NOT catch
 * seven tiers that agree on the wrong rewrite — `BigintBigLessEq` lowered to
 * `<`, say, which is a plausible copy-paste and which every tier would then
 * emit identically. Only comparison against the operator spelling distinguishes
 * "they agree" from "they are right", and the six comparison helpers are
 * asserted below in the direction that makes each one true for `a < b`, so any
 * two of them swapped changes the bytes.
 *
 * Keep the two files in lockstep: same contract shape, same property, same
 * method names, same parameter names, same binding names, same order. The
 * claim is byte equality, and any of those changes it.
 */
class GoBigintBigOperatorsRef extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public checkArithmetic(a: bigint, b: bigint) {
    const sum = a + b;
    const diff = a - b;
    const prod = a * b;
    const quot = a / b;
    const rem = a % b;
    const total = sum + diff + (prod + (quot + rem));
    assert(total === this.expected);
  }

  public checkWideEncoders(a: bigint) {
    const encoded = num2bin(a, 8n);
    assert(bin2num(encoded) === this.expected);
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
