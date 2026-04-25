package runar.examples.stateful;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * Stateful -- minimal stateful conformance fixture that mixes a mutable
 * {@code count} with an immutable {@code maxCount} ceiling. Demonstrates
 * the two-property state-continuation lowering.
 */
class Stateful extends StatefulSmartContract {

    Bigint count;
    @Readonly Bigint maxCount;

    Stateful(Bigint count, Bigint maxCount) {
        super(count, maxCount);
        this.count = count;
        this.maxCount = maxCount;
    }

    @Public
    void increment(Bigint amount) {
        this.count = this.count.plus(amount);
        assertThat(this.count.le(this.maxCount));
    }

    @Public
    void reset() {
        this.count = Bigint.ZERO;
    }
}
