package runar.conformance.stateledger;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * Ledger -- F-352 second witness for the mutable-state shape
 * {PubKey, bigint, bigint}.
 */
class Ledger extends StatefulSmartContract {

    PubKey holder;
    Bigint balance;
    Bigint nonce;

    Ledger(PubKey holder, Bigint balance, Bigint nonce) {
        super(holder, balance, nonce);
        this.holder = holder;
        this.balance = balance;
        this.nonce = nonce;
    }

    @Public
    void spend(Sig sig, Bigint amount) {
        assertThat(checkSig(sig, this.holder));
        assertThat(amount.gt(Bigint.ZERO));
        assertThat(amount.le(this.balance));
        this.balance = this.balance.minus(amount);
        this.nonce = this.nonce.plus(Bigint.ONE);
    }
}
