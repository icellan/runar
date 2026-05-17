package runar.examples.intentcurrentblockheight;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.currentBlockHeight;

/**
 * IntentCurrentBlockHeight -- exercises the {@code currentBlockHeight}
 * shorthand, which is pure source-level sugar for
 * {@code extractLocktime(this.txPreimage)}.
 */
class IntentCurrentBlockHeight extends StatefulSmartContract {

    @Readonly Bigint deadline;
    Bigint count;

    IntentCurrentBlockHeight(Bigint deadline, Bigint count) {
        super(deadline, count);
        this.deadline = deadline;
        this.count = count;
    }

    @Public
    void spend() {
        Bigint h = Bigint.of(currentBlockHeight());
        assertThat(h.le(this.deadline));
        this.count = this.count.plus(Bigint.ONE);
    }
}
