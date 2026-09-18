import { SmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

/**
 * ArrayIndex — the dynamic-index read of a `FixedArray`, on a stateless
 * contract, in all nine surface syntaxes.
 *
 * `Grid2x2` covers array literals and LITERAL-index access. It does not cover
 * `this.table[i]` where `i` is a runtime value, which is the path the
 * expand-fixed-arrays pass lowers into a chain of index comparisons — and the
 * path behind three of the four FixedArray defects this audit found.
 *
 * Stateless on purpose: it makes the fixture reachable by the differential
 * execution oracle (`conformance/witnesses/`), which drives spends through the
 * ANF interpreter and the @bsv/sdk ScriptVM and today has no stateful lane.
 */
export class ArrayIndex extends SmartContract {
  readonly table: FixedArray<bigint, 4> = [10n, 20n, 30n, 40n];

  constructor() {
    super();
  }

  public lookup(i: bigint, expected: bigint) {
    assert(this.table[i] === expected);
  }
}
