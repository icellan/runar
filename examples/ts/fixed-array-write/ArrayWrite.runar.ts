import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

/**
 * ArrayWrite — the runtime-index WRITE of a `FixedArray`, in all nine surface
 * syntaxes, as `this.table[i]++`.
 *
 * This is R-094's testable assertion verbatim. The construct had a fund-loss
 * defect in six tiers (N-019 / `4c062371`): pass 3b desugared only the
 * increment's operand into a read dispatch, so the increment lowering and the
 * mutates-state summary both saw a ternary and dropped the write — a stateful
 * method that mutates state compiled with NO continuation covenant. Nothing
 * gated it, because FixedArray had zero conformance fixtures.
 */
export class ArrayWrite extends StatefulSmartContract {
  table: FixedArray<bigint, 4> = [0n, 0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.table[i]++;
    assert(true);
  }
}
