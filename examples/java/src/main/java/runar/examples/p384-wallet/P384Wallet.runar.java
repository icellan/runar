package runar.examples.p384wallet;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;
import static runar.lang.Builtins.verifyECDSA_P384;

class P384Wallet extends SmartContract {

    @Readonly Addr ecdsaPubKeyHash;
    @Readonly ByteString p384PubKeyHash;

    P384Wallet(Addr ecdsaPubKeyHash, ByteString p384PubKeyHash) {
        super(ecdsaPubKeyHash, p384PubKeyHash);
        this.ecdsaPubKeyHash = ecdsaPubKeyHash;
        this.p384PubKeyHash = p384PubKeyHash;
    }

    @Public
    void spend(ByteString p384Sig, ByteString p384PubKey, Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(ecdsaPubKeyHash));
        assertThat(checkSig(sig, pubKey));

        assertThat(hash160(p384PubKey).equals(p384PubKeyHash));
        assertThat(verifyECDSA_P384(sig, p384Sig, p384PubKey));
    }
}
