import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

/**
 * ArraySet -- F-352 second witness for the mutable-state shape
 * FixedArray<bigint, 4> (the first is `fixed-array-write`, which increments).
 * This one assigns a caller-supplied value at a runtime index. No Java
 * surface: FixedArray is unsupported there (see source.json parserSkipReason).
 */
export class ArraySet extends StatefulSmartContract {
  slots: FixedArray<bigint, 4> = [0n, 0n, 0n, 0n];

  constructor() {
    super();
  }

  public put(i: bigint, v: bigint) {
    // Rúnar indexes a FixedArray with a bigint; the TS lib types the index as number.
    // @ts-expect-error bigint index
    this.slots[i] = v;
    assert(true);
  }
}
