// R-073 / CL-BUG-168: writing a ByteString into a `FixedArray<bigint, 3>` slot
// is a type error. Six tiers rejected it; the Zig tier's typechecker returned
// from its `.assign` arm as soon as the target carried an index, so the value
// was never compared against the array's element type and this source compiled
// to a full 1274-byte locking script.
//
// A rejection-parity fixture rather than a Zig-tier unit test because the
// defect was invisible from inside one tier: the tier agreed with itself.
import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray, ByteString } from 'runar-lang';

export class CellProbe extends StatefulSmartContract {
  readonly owner: bigint;
  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor(owner: bigint) {
    super(owner);
    this.owner = owner;
  }

  public setBad(v: ByteString) {
    assert(this.owner > 0n);
    this.cells[0] = v;
  }
}
