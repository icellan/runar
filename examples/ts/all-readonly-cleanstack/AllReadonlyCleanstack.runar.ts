import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

/**
 * AllReadonlyCleanstack — regression fixture for issue #44.
 *
 * A {@link StatefulSmartContract} subclass with ZERO mutable fields (only a
 * readonly `owner`) plus a readonly-field-binding in a terminal method. The
 * `const ownerCopy = this.owner` binding force-embeds the readonly field onto
 * the stack; it is not consumed by the terminal `checkSig` assertion, so it
 * leaves an excess stack item below the top-of-stack boolean.
 *
 * Bitcoin Script's CLEANSTACK rule requires exactly one item on the stack at
 * end-of-script. Before the fix, `cleanupExcessStack()` was gated behind a
 * `hasDeserializeState` check — which is never true for an all-readonly
 * stateful contract — so the leftover item survived and the spend was rejected
 * on mainnet with "Script did not clean its stack". The fix runs
 * `cleanupExcessStack()` for every public method (it is a no-op when the stack
 * is already balanced), emitting the trailing `OP_NIP` that balances the stack.
 */
class AllReadonlyCleanstack extends StatefulSmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public claim(sig: Sig): void {
    const ownerCopy = this.owner;
    assert(checkSig(sig, this.owner));
  }
}
