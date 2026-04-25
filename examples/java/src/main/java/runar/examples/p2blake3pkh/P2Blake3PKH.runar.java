package runar.examples.p2blake3pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.blake3Hash;
import static runar.lang.Builtins.checkSig;

class P2Blake3PKH extends SmartContract {

    @Readonly ByteString pubKeyHash;

    P2Blake3PKH(ByteString pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(blake3Hash(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
