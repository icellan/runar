package runar.examples.postquantumslhdsa;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.verifySLHDSA_SHA2_128s;

/**
 * PostQuantumSLHDSA -- minimal conformance fixture exercising the
 * FIPS 205 SLH-DSA (SHA2-128s) signature verification primitive.
 */
class PostQuantumSLHDSA extends SmartContract {

    @Readonly ByteString pubkey;

    PostQuantumSLHDSA(ByteString pubkey) {
        super(pubkey);
        this.pubkey = pubkey;
    }

    @Public
    void spend(ByteString msg, ByteString sig) {
        assertThat(verifySLHDSA_SHA2_128s(msg, sig, this.pubkey));
    }
}
