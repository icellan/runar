package runar.examples.sighashsinglestateful;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Sighash;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.extractAmount;

/**
 * SingleCounter -- Java port of
 * {@code examples/ts/sighash-single-stateful/SingleCounter.runar.ts}.
 *
 * <p>{@code bump} carries {@code Sighash("SINGLE|FORKID")} (N-093), so its
 * auto-injected continuation commits only the output at its own index: no
 * change segment and no {@code _changePKH} / {@code _changeAmount} parameter
 * (N-038). SINGLE does not pin the continuation's value, so {@code bump}
 * re-creates it at the full input amount read from the preimage.
 * {@code reset} keeps ALL|FORKID.
 */
class SingleCounter extends StatefulSmartContract {

    Bigint count;

    SingleCounter(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    @Sighash("SINGLE|FORKID")
    void bump() {
        this.addOutput(extractAmount(this.txPreimage), this.count.plus(Bigint.ONE));
    }

    @Public
    void reset() {
        assertThat(this.count.gt(Bigint.ZERO));
        this.count = Bigint.ZERO;
    }
}
