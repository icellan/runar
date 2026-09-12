// N-105: `this.addRawOutput(...)` with a third argument.
//
// The intrinsic takes exactly (satoshis, scriptBytes). The TypeScript reference
// refuses this source ("addRawOutput() expects 2 arguments (satoshis,
// scriptBytes), got 3"); the other six tiers accepted it and SILENTLY DROPPED
// the surplus argument — the Go tier emitted 1524 hexchars for this source, a
// script in which the third operand appears nowhere. A call the author wrote is
// not in the covenant, with no diagnostic.
//
// The one-argument form is the same rule and was not silent: it crashed in a
// later pass in every tier ("index out of range", "value '' not found on
// stack", "InvalidBuiltin"), which is a compiler bug report rather than a
// language verdict. Both now answer with the same frontend diagnostic.
//
// `addDataOutput` carries the identical arity contract and had the same hole;
// every tier routes both through one check.
//
// The shape stays invalid regardless of how inference evolves: the arity is
// fixed by the intrinsic, not inferred.
import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

export class RawOutputArity extends StatefulSmartContract {
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
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.blob, 7n);
  }
}
