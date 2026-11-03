package runar.examples.multisigverifyfused;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkMultiSig;

class MultiSigVerifyFused extends SmartContract {

    @Readonly PubKey pk1;
    @Readonly PubKey pk2;
    @Readonly PubKey pk3;

    MultiSigVerifyFused(PubKey pk1, PubKey pk2, PubKey pk3) {
        super(pk1, pk2, pk3);
        this.pk1 = pk1;
        this.pk2 = pk2;
        this.pk3 = pk3;
    }

    @Public
    void unlock(Sig sig1, Sig sig2, Bigint amount) {
        assertThat(checkMultiSig(
            new Sig[]{sig1, sig2},
            new PubKey[]{this.pk1, this.pk2, this.pk3}));
        assertThat(amount.gt(Bigint.ZERO));
    }
}
