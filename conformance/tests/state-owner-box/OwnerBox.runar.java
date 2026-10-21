package runar.conformance.stateownerbox;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * OwnerBox -- F-352 second witness for the mutable-state shape {PubKey}.
 */
class OwnerBox extends StatefulSmartContract {

    PubKey owner;

    OwnerBox(PubKey owner) {
        super(owner);
        this.owner = owner;
    }

    @Public
    void rotate(Sig sig, PubKey newOwner) {
        assertThat(checkSig(sig, this.owner));
        this.owner = newOwner;
    }
}
