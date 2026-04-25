package runar.examples.multimethod;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * MultiMethod -- exercises multiple public methods plus a {@code private}
 * helper that gets inlined by the compiler. Demonstrates owner/backup
 * dual spending paths, each gated by a different signature.
 */
class MultiMethod extends SmartContract {

    @Readonly PubKey owner;
    @Readonly PubKey backup;

    MultiMethod(PubKey owner, PubKey backup) {
        super(owner, backup);
        this.owner = owner;
        this.backup = backup;
    }

    private Bigint computeThreshold(Bigint a, Bigint b) {
        return a.times(b).plus(Bigint.ONE);
    }

    @Public
    void spendWithOwner(Sig sig, Bigint amount) {
        Bigint threshold = this.computeThreshold(amount, Bigint.TWO);
        assertThat(threshold.gt(Bigint.of(10)));
        assertThat(checkSig(sig, this.owner));
    }

    @Public
    void spendWithBackup(Sig sig) {
        assertThat(checkSig(sig, this.backup));
    }
}
