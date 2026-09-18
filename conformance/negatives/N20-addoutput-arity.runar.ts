// N-105: `this.addOutput(...)` with the wrong NUMBER of state values.
//
// The TypeScript reference refuses this source ("addOutput() expects 3
// argument(s): satoshis + 2 state value(s), got 2"); the other six tiers
// accepted it and emitted a covenant with the missing value simply ABSENT from
// the continuation. Measured through the Go tier on a one-mutable-property
// contract: the correct `addOutput(1000n, this.count)` emits 1362 hexchars and
// the short `addOutput(1000n)` emits 1352 — a DIFFERENT script, not a rejected
// one. The state write the author asked for is not in the output the covenant
// commits to.
//
// The mirror case (a SURPLUS value) is worse in the other direction: the extra
// value is appended to a state serialization that the next spend deserializes
// by fixed offsets, so every field after it reads the wrong bytes. Both go
// through the same rule; this fixture pins the short form because it is the one
// a developer reaches by adding a state property and forgetting a call site.
//
// The shape stays invalid regardless of how inference evolves: the arity is
// derived from the contract's own mutable properties, which are right here in
// the source.
import { StatefulSmartContract, PubKey, assert } from 'runar-lang';

export class AddOutputArity extends StatefulSmartContract {
  count: bigint;
  owner: PubKey;

  constructor(count: bigint, owner: PubKey) {
    super(count, owner);
    this.count = count;
    this.owner = owner;
  }

  public bump(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count);
  }
}
