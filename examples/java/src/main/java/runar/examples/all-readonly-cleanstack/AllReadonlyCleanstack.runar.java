package runar.examples.allreadonlycleanstack;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * AllReadonlyCleanstack -- regression fixture for issue #44.
 *
 * <p>A {@link StatefulSmartContract} with ZERO mutable fields (only a readonly
 * {@code owner}) plus a readonly-field-binding in a terminal method. The
 * {@code ownerCopy = this.owner} binding force-embeds the readonly field onto
 * the stack; it is not consumed by the terminal {@code checkSig} assertion,
 * leaving an excess stack item below the top-of-stack boolean.
 *
 * <p>Bitcoin Script's CLEANSTACK rule requires exactly one item on the stack at
 * end-of-script. Before the fix, the leftover survived and the spend was
 * rejected on mainnet with "Script did not clean its stack". The fix runs the
 * stack cleanup for every public method, emitting the trailing {@code OP_NIP}
 * that balances the stack.
 */
class AllReadonlyCleanstack extends StatefulSmartContract {

    @Readonly PubKey owner;

    AllReadonlyCleanstack(PubKey owner) {
        super(owner);
        this.owner = owner;
    }

    @Public
    void claim(Sig sig) {
        PubKey ownerCopy = this.owner;
        assertThat(checkSig(sig, this.owner));
    }
}
