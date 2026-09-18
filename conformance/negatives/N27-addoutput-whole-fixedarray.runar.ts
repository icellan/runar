// N-107 — passing a FixedArray state property WHOLE to `addOutput` is refused.
//
// The companion to N26. `addOutput(1000n, this.board, this.n)` is the shape the
// reference tier's OLD arity rule demanded — it counted `board` as one state
// value — and it has never been a shape that lowers: `board` is not a scalar,
// has no stack slot of its own after expansion, and six tiers died on it deep
// in stack lowering with "property 'board' ... is neither on the stack,
// initialized, nor a constructor parameter". A rule that accepts a program its
// own backend cannot lower is worse than one that rejects it, because the
// diagnostic arrives from the wrong pass and names the wrong thing.
//
// With the arity rule counting expanded slots, this is now refused in the
// frontend by every tier: four state slots are required and two were supplied.
import { StatefulSmartContract } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class WholeArrayOutput extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.addOutput(1000n, this.board, this.n); }
}
