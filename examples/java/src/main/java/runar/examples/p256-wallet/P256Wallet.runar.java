package runar.examples.p256wallet;

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
import static runar.lang.Builtins.verifyECDSA_P256;

class P256Wallet extends SmartContract {

    @Readonly Addr ecdsaPubKeyHash;
    @Readonly ByteString p256PubKeyHash;

    P256Wallet(Addr ecdsaPubKeyHash, ByteString p256PubKeyHash) {
        super(ecdsaPubKeyHash, p256PubKeyHash);
        this.ecdsaPubKeyHash = ecdsaPubKeyHash;
        this.p256PubKeyHash = p256PubKeyHash;
    }

    @Public
    void spend(ByteString p256Sig, ByteString p256PubKey, Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(ecdsaPubKeyHash));
        assertThat(checkSig(sig, pubKey));

        assertThat(hash160(p256PubKey).equals(p256PubKeyHash));
        // The secp256k1 signature bytes are themselves the message that
        // P-256 signs — Sig extends ByteString so we pass it directly.
        assertThat(verifyECDSA_P256(sig, p256Sig, p256PubKey));
    }
}
