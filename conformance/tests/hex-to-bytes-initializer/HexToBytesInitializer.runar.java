package runar.examples.hextobytesinitializer;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

class HexToBytesInitializer extends SmartContract {

    @Readonly ByteString p2pkhPrefix = ByteString.fromHex("1976a914");
    @Readonly ByteString p2pkhSuffix = ByteString.fromHex("88ac");
    @Readonly Addr pubKeyHash;

    HexToBytesInitializer(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey, ByteString script) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(cat(cat(p2pkhPrefix, pubKeyHash), p2pkhSuffix).equals(script));
        assertThat(checkSig(sig, pubKey));
    }
}
