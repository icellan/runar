package runar.conformance.statenotary;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * Notary -- F-352 second witness for the mutable-state shape
 * {ByteString, PubKey, bigint}, with the PubKey declared first.
 */
class Notary extends StatefulSmartContract {

    PubKey signer;
    ByteString note;
    Bigint seq;

    Notary(PubKey signer, ByteString note, Bigint seq) {
        super(signer, note, seq);
        this.signer = signer;
        this.note = note;
        this.seq = seq;
    }

    @Public
    void notarize(Sig sig, ByteString nextNote) {
        assertThat(checkSig(sig, this.signer));
        this.note = nextNote;
        this.seq = this.seq.plus(Bigint.ONE);
    }
}
