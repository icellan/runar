import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

/**
 * Grid2x2 — minimal nested `FixedArray<FixedArray<bigint, 2>, 2>`
 * acceptance contract for the TS spike.
 *
 * The expand-fixed-arrays pass desugars `grid` into four scalar siblings
 * `grid__0__0`, `grid__0__1`, `grid__1__0`, `grid__1__1`. Pass 3b
 * attaches a two-element `__syntheticArrayChain` to each leaf, and the
 * iterative regrouper in the artifact assembler rebuilds a single
 * nested FixedArray state field so the SDK exposes `state.grid` as a
 * real JS `bigint[][]` matching the declared shape.
 *
 * Runtime indexing into a nested FixedArray is intentionally still a
 * compile error for the v1 spike, so each write is split into its own
 * literal-index method.
 */
export class Grid2x2 extends StatefulSmartContract {
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public set00(v: bigint) {
    this.grid[0][0] = v;
    assert(true);
  }

  public set01(v: bigint) {
    this.grid[0][1] = v;
    assert(true);
  }

  public set10(v: bigint) {
    this.grid[1][0] = v;
    assert(true);
  }

  public set11(v: bigint) {
    this.grid[1][1] = v;
    assert(true);
  }

  public read00() {
    assert(this.grid[0][0] == this.grid[0][0]);
  }
}
