// N-092: a FixedArray may not be a CONSTRUCTOR PARAMETER.
//
// A property's deploy-time value reaches the locking script through a
// constructor slot: the SDK splices `constructorArgs[slot.paramIndex]` into the
// bytes that slot names. `expand_fixed_arrays` splits a FixedArray PROPERTY
// into scalar siblings, but a constructor PARAMETER has no such expansion, so
// there is nothing for an argument to be spliced into. Five tiers (ts, go,
// rust, python, java) refuse the shape outright for exactly that reason:
//
//   "Constructor parameter 'xs' cannot be a FixedArray. Use initialized
//    properties or pass each element as a separate parameter."
//
// Zig and Ruby never received the rule. Both COMPILED this source to a
// byte-identical 480-byte stateful locking script whose `constructorSlots` is
// EMPTY — a deployable script for a contract whose only state property can
// never be given a deploy-time value. That is the funds-relevant half of this
// fixture: the divergence was not a missing warning, it was a script.
//
// The method body deliberately does NOT read `xs`. The original probe asserted
// `this.xs[0] >= 0n`, which the Zig tier rejected for an unrelated reason
// ("left operand of '>=' must be bigint, got 'unknown'"), masking the fact that
// the constructor rule was absent. A fixture that is rejected for the wrong
// reason is a vacuous fixture.
//
// The supported form — a FixedArray property with a literal initializer — is
// exercised by the conformance corpus and must keep compiling; only the
// constructor PARAMETER is refused.
import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class CtorFixedArray extends StatefulSmartContract {
  xs: FixedArray<bigint, 3>;

  constructor(xs: FixedArray<bigint, 3>) {
    super(xs);
    this.xs = xs;
  }

  public go(i: bigint) {
    assert(i >= 0n);
  }
}
