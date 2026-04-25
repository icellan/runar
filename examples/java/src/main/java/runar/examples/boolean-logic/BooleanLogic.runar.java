package runar.examples.booleanlogic;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * BooleanLogic -- exercises Java's logical operators (&&, ||, !) on
 * boolean expressions derived from {@link Bigint} comparisons.
 */
class BooleanLogic extends SmartContract {

    @Readonly Bigint threshold;

    BooleanLogic(Bigint threshold) {
        super(threshold);
        this.threshold = threshold;
    }

    @Public
    void verify(Bigint a, Bigint b, boolean flag) {
        boolean aAboveThreshold = a.gt(this.threshold);
        boolean bAboveThreshold = b.gt(this.threshold);
        boolean bothAbove = aAboveThreshold && bAboveThreshold;
        boolean eitherAbove = aAboveThreshold || bAboveThreshold;
        boolean notFlag = !flag;
        assertThat(bothAbove || (eitherAbove && notFlag));
    }
}
