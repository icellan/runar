import { StatefulSmartContract } from 'runar-lang';

/**
 * Issue #178 / ports #179 — the two ways a branch arm reordered the slots it
 * inherits from the enclosing scope while keeping the same names at the same
 * depth. The sibling arm and the parent kept the old order, so after the `if`
 * the taken path read a neighbouring slot into the committed state.
 *
 * deadRebind:    `w` is dead after the `if`; rebinding it consumed its slot and
 *                pushed the new value on top, over `k`, so `this.a = k` took
 *                the rebound `w`.
 * nestedRebind:  a nested `if` without `else` rebinds the live `na`, leaving the
 *                new value on top of `nb`, so `a` and `b` swapped.
 * siblingsAbove: the same under three siblings; the then-arm has to sink `na`
 *                back under all three.
 *
 * The ANF is unaffected (this is a stack-lowering bug), so the interpreter
 * goldens are the source values; the scriptOracle block in each input spends
 * the compiled script on @bsv/sdk Spend and is what fails without the fix.
 */
class BranchPermutedParentSlots extends StatefulSmartContract {
  a: bigint;
  b: bigint;
  c: bigint;

  constructor(a: bigint, b: bigint, c: bigint) {
    super(a, b, c);
    this.a = a;
    this.b = b;
    this.c = c;
  }

  public deadRebind(x: bigint, flag: bigint) {
    let w: bigint = x + 1n;
    let k: bigint = x + 2n;
    if (flag > 0n) {
      w = w - 1n;
    }
    this.a = k;
  }

  public nestedRebind(x: bigint, outer: bigint, inner: bigint) {
    let na: bigint = this.a;
    let nb: bigint = this.b;
    if (outer > 0n) {
      if (inner > 0n) {
        na = x + 1n;
      }
    }
    this.a = na;
    this.b = nb;
  }

  public siblingsAbove(x: bigint, outer: bigint, inner: bigint) {
    let na: bigint = this.a;
    let s1: bigint = x + 1n;
    let s2: bigint = x + 2n;
    let s3: bigint = x + 3n;
    if (outer > 0n) {
      if (inner > 0n) {
        na = x;
      }
    }
    this.a = na;
    this.b = s1 + s2;
    this.c = s3;
  }
}
