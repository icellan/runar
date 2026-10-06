// N-029 — the cross-tier gate on the constant folder computing exactly what
// the emitted script computes, in the one place that compiles with CONSTANT
// FOLDING ON (no fold flag is passed — see subtype-parity.test.ts).
//
// Three builtins used to fold to a value the script does not compute:
//
//   - clamp(v, lo, hi) lowers to `<v> <lo> OP_MAX <hi> OP_MIN`, i.e.
//     min(max(v, lo), hi). Six tiers folded `v < lo ? lo : ...` (or the
//     equivalent max(lo, min(v, hi))), which differs once lo > hi:
//     clamp(5, 10, 0) is 0 on-chain and folded to 10. Rust alone folded it
//     right, so the tiers also disagreed with each other.
//   - log2 unrolls 64 halvings, so it saturates at 64 for n >= 2^65. Every
//     tier folded the true floor(log2 n).
//   - gcd unrolls 256 Euclid steps and returns a partial remainder when more
//     are needed. Every tier folded the true gcd.
//
// Every tier must now fold the in-domain calls below to the same value and
// DECLINE the out-of-domain ones, leaving the script fragment in the compared
// bytes. A tier that folds a declined call (or declines a foldable one) emits
// different hex and fails the byte-identity check. The script values are
// executed on @bsv/sdk Spend.validate, in both fold modes, by
// packages/runar-testing/src/__tests__/n029-fold-builtin-script-parity.test.ts.
import { SmartContract, assert, clamp, log2, gcd } from 'runar-lang';

export class FoldBuiltinScriptParity extends SmartContract {
  readonly tag: bigint;

  constructor(tag: bigint) {
    super(tag);
    this.tag = tag;
  }

  public unlock(x: bigint) {
    // lo > hi: the script's OP_MIN runs last, so every tier folds this to 0.
    const clamped: bigint = clamp(5n, 10n, 0n);
    // 2^64: exactly 64 halvings, inside the unroll — every tier folds to 64.
    const log2In: bigint = log2(18446744073709551616n);
    // 2^70: past the unroll — no tier may fold it.
    const log2Out: bigint = log2(1180591620717411303424n);
    // gcd(F258, F257) takes exactly 256 Euclid steps — every tier folds to 1.
    const gcdIn: bigint = gcd(
      370959230771131880927453318055001997489772178180790104n,
      229265413057075367692743352179590077832064383222590237n,
    );
    // gcd(F259, F258) takes 257 — no tier may fold it.
    const gcdOut: bigint = gcd(
      600224643828207248620196670234592075321836561403380341n,
      370959230771131880927453318055001997489772178180790104n,
    );

    assert(clamped + log2In + log2Out + gcdIn + gcdOut === x + this.tag);
  }
}
