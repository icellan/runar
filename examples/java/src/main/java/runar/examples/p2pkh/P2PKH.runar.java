package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

// Contract classes in .runar.java files are package-private so that javac
// accepts the compound .runar.java suffix (which does not match a bare
// public class name). Cross-package consumers use the typed wrappers
// emitted by the Rúnar SDK codegen (milestone 10).
class P2PKH extends SmartContract {

    @Readonly Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
