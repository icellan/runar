package runar.examples.boundedloop;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * BoundedLoop -- exercises a fixed-iteration {@code for} loop that
 * accumulates a sum across {@code start + i} for {@code i in [0, 5)}.
 * The unlock succeeds iff the resulting sum matches the stored
 * {@code expectedSum}.
 */
class BoundedLoop extends SmartContract {

    @Readonly Bigint expectedSum;

    BoundedLoop(Bigint expectedSum) {
        super(expectedSum);
        this.expectedSum = expectedSum;
    }

    @Public
    void verify(Bigint start) {
        Bigint sum = Bigint.ZERO;
        for (Bigint i = Bigint.ZERO; i.lt(Bigint.of(5)); i = i.plus(Bigint.ONE)) {
            sum = sum.plus(start).plus(i);
        }
        assertThat(sum.eq(this.expectedSum));
    }
}
