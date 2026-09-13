// R-173 (CL-BUG-152) — `getStateScript()` called with arguments.
//
// The builtin takes none: it returns the contract's own state script, which is
// a property of the contract, not of anything a caller could pass. Five tiers
// accepted the call and DISCARDED the arguments — the emitted hex is identical
// to the zero-argument spelling, byte for byte:
//
//   go   getStateScript(n, n + 1n)   1372 hexchars  sha 29aaaa262973
//   go   getStateScript()            1372 hexchars  sha 29aaaa262973
//
// So an author who believed the arguments meant something got a script that
// ignored them, with no diagnostic. Measured across all seven:
//
//   ts     exit 1  "getStateScript() takes no arguments"
//   rust   exit 1  type-check error
//   go / python / zig / ruby / java   exit 0
//
// That is invariant 1 — frontend parity, no exceptions — failing 2 against 5,
// and the two that refuse are the reference tier and one peer. The message
// below is the reference tier's, word for word.

import { StatefulSmartContract, assert, len, ByteString } from 'runar-lang';

class GetStateScriptArity extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(n: bigint) {
    const s: ByteString = this.getStateScript(n, n + 1n);
    this.count = this.count + 1n;
    assert(len(s) > 0n);
  }
}
