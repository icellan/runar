// R-105 — the minimal stateful contract, used to extract each tier's
// OP_PUSH_TX preimage-binding blob.
//
// `checkPreimage` is auto-injected for every public method of a
// StatefulSmartContract, so any stateful contract carries the blob. This one is
// deliberately the smallest that does — one mutable field, one method — so the
// blob dominates the emitted script and an extraction failure is obvious.
import { StatefulSmartContract, assert } from 'runar-lang';

export class StatefulBinding extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public bump() {
    const old = this.count++;
    assert(old >= 0n);
  }
}
