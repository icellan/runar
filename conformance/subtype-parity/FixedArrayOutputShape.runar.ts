// N-106 / N-107 — the positive half: `addOutput` over EXPANDED FixedArray state.
//
// This is the `Boardy` contract checked into
// `compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py`,
// which six tiers compiled and the TypeScript REFERENCE refused. The reference
// counted `addOutput`'s arity over the DECLARED mutable properties (`board`,
// `n` — two) while `expandFixedArrays`, which runs right after the typechecker,
// splits `board` into `board__0 .. board__2`, so the continuation carries four.
// The only call shape that lowers is therefore the five-argument one written
// here, and the reference answered "expects 3 argument(s) ... got 5".
//
// It belongs in this corpus for the reason the corpus exists: the failure is an
// ACCEPTANCE divergence, invisible to `conformance/negatives/`, and byte
// identity is the second half of the claim — six tiers agreeing to accept a
// source while emitting different continuations would be worse than the split.
//
// N26 / N27 in `conformance/negatives/` are the two rejection halves.
import { StatefulSmartContract } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class FixedArrayOutputShape extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void {
    this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n);
  }
}
