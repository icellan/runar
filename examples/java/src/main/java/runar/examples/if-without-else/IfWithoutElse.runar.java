package runar.examples.ifwithoutelse;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * IfWithoutElse -- exercises {@code if} branches with no {@code else}
 * arm. The unlock counts how many of {@code a} and {@code b} exceed
 * the stored threshold and requires at least one to qualify.
 */
class IfWithoutElse extends SmartContract {

    @Readonly Bigint threshold;

    IfWithoutElse(Bigint threshold) {
        super(threshold);
        this.threshold = threshold;
    }

    @Public
    void check(Bigint a, Bigint b) {
        Bigint count = Bigint.ZERO;
        if (a.gt(this.threshold)) { count = count.plus(Bigint.ONE); }
        if (b.gt(this.threshold)) { count = count.plus(Bigint.ONE); }
        assertThat(count.gt(Bigint.ZERO));
    }
}
