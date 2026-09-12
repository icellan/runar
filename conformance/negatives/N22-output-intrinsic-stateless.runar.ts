// N-105: an output intrinsic in a STATELESS contract.
//
// `addOutput` / `addRawOutput` / `addDataOutput` build the continuation output
// of a covenant, which only exists for a StatefulSmartContract. The TypeScript
// reference refuses this source ("addRawOutput() is only available in
// StatefulSmartContract"), and so did the Zig tier with its own wording; go,
// rust, python, ruby and java ACCEPTED it and emitted a 152-hexchar script —
// a "continuation" for a contract that has no state to continue.
//
// `addOutput` in the same position did not survive either: the five accepting
// tiers took it through to stack lowering and died there on `_codePart`, which
// is a crash in a later pass rather than a frontend verdict. `addRawOutput`
// does not even do that, because it needs no codePart — it just compiles.
//
// The shape stays invalid regardless of how inference evolves: the base class is
// declared in this source.
import { SmartContract, ByteString, assert } from 'runar-lang';

export class StatelessOutput extends SmartContract {
  readonly blob: ByteString;

  constructor(blob: ByteString) {
    super(blob);
    this.blob = blob;
  }

  public unlock(n: bigint) {
    this.addRawOutput(1000n, this.blob);
    assert(n > 0n);
  }
}
