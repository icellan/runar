/**
 * R-010 probe: a StatefulSmartContract with ZERO mutable properties that
 * still builds a state-continuation output.
 *
 * `fixedStateSectionLength()` sums the widths of the mutable properties, so
 * with none it answers 0 — which the clause-8a branch read as "a fixed state
 * section of length zero" and turned into `SIZE(rest) == 1`, plus clause 8b
 * demanding a trailing `0x6a`. The artifact for this shape carries NO
 * `stateFields` at all, so the SDK's `getLockingScript()` appends neither
 * separator nor payload: the remainder is ZERO bytes against a clause
 * demanding one, and every honest spend aborts at OP_NUMEQUALVERIFY.
 *
 * The explicit `addOutput` is load-bearing. Without it no continuation output
 * is built, `_codePart` never reaches the stack, and
 * `emitCodePartAuthentication` never runs — which is why the plain
 * zero-mutable shape looks harmless.
 */
import { StatefulSmartContract, assert } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class ZeroMutableContinuation extends StatefulSmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public spend(sig: Sig, amount: bigint) {
    assert(amount > 0n);
    this.addOutput(amount);
  }
}
