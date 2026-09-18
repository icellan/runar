// N-105: a ByteString passed where `this.addOutput(...)` expects a bigint state
// value.
//
// The TypeScript reference refuses this source ("addOutput() argument 2 (count)
// must be 'bigint', got 'ByteString'"); the other six tiers accepted it and
// serialized the ByteString into the state slot an 8-byte little-endian number
// belongs in. Measured through the Go tier: the rejected source and the correct
// one both emit 1362 hexchars but DIFFERENT bytes, so this is not a missing
// diagnostic — the covenant commits to a continuation whose state field is the
// wrong width and the wrong encoding, and the next spend's deserializer reads
// it by fixed offsets.
//
// Same family as N16 (a ByteString in the satoshis slot) and N19 (a number in
// the scriptBytes slot): the operand is not converted, it is just put where it
// does not belong.
//
// The shape stays invalid regardless of how inference evolves: `ByteString` is
// not a member of the bigint family under any tier's rule.
import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

export class StateValueType extends StatefulSmartContract {
  count: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, blob: ByteString) {
    super(count, blob);
    this.count = count;
    this.blob = blob;
  }

  public bump(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.blob);
  }
}
