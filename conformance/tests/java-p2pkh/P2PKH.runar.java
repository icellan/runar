package runar.examples.p2pkh;

import runar.lang.*;

public class P2PKH extends SmartContract {
    @Readonly Addr pubKeyHash;

    public P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    public void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
