// N-106 / N-107 — `addOutput` arity must be counted over the EXPANDED state.
//
// `board: FixedArray<bigint, 3>` is one DECLARED mutable property and FOUR
// emitted state slots: `expandFixedArrays` (pass 3b) splits it into
// `board__0 .. board__2`, and the continuation carries those three plus `n`.
// So `addOutput(satoshis, ...)` here needs 1 + 4 = 5 arguments. This fixture
// passes 4 and must be refused by every tier.
//
// Before the fix nobody counted it that way for the right reason:
//
//   * five tiers (go / rust / python / zig / ruby) SCOPED THE RULE OUT of any
//     contract with FixedArray state (`shapeCheckable := !hasFixedArrayState`)
//     and ACCEPTED this source, emitting a locking script whose state
//     continuation is one slot short of the contract's own state. A stateful
//     contract that commits to the wrong number of state values is a
//     fund-relevant defect, not a diagnostic nicety.
//   * the TypeScript reference rejected it, but for the wrong reason and with
//     the wrong number — its rule counts DECLARED properties, so it answered
//     "expects 3 argument(s): satoshis + 2 state value(s)". The same rule made
//     it refuse the CORRECT 5-argument form too, which is why no accepted way
//     to call addOutput from a FixedArray contract existed in the reference.
//   * Java alone got the number right, and only by accident: it ran
//     ExpandFixedArrays BEFORE Typecheck (N-106), so its typechecker was
//     looking at the already-expanded property list.
//
// That is the single root cause behind both findings. The fix computes the
// expanded slot view inside the rule, in all seven tiers, which then lets
// Java's pass order be corrected without losing the count.
//
// The POSITIVE control is `conformance/subtype-parity/FixedArrayOutputShape.runar.ts`
// — the same contract with the correct five arguments, which every tier must
// accept and compile to identical bytes.
import { StatefulSmartContract } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class ArityUnderFixedArray extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.addOutput(1000n, this.board[0], this.board[1], this.n); }
}
