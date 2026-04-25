package runar.examples.postquantumwots;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.verifyWOTS;

/**
 * PostQuantumWOTS -- minimal conformance fixture exercising the
 * one-time WOTS+ post-quantum signature verification primitive.
 */
class PostQuantumWOTS extends SmartContract {

    @Readonly ByteString pubkey;

    PostQuantumWOTS(ByteString pubkey) {
        super(pubkey);
        this.pubkey = pubkey;
    }

    @Public
    void spend(ByteString msg, ByteString sig) {
        assertThat(verifyWOTS(msg, sig, this.pubkey));
    }
}
