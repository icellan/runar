package runar.examples.ifelse;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * IfElse -- exercises {@code if/else} branching with mutable local
 * variable assignment. The unlock requires the resulting value to be
 * positive after picking the addition or subtraction branch.
 */
class IfElse extends SmartContract {

    @Readonly Bigint limit;

    IfElse(Bigint limit) {
        super(limit);
        this.limit = limit;
    }

    @Public
    void check(Bigint value, boolean mode) {
        Bigint result = Bigint.ZERO;
        if (mode) {
            result = value.plus(this.limit);
        } else {
            result = value.minus(this.limit);
        }
        assertThat(result.gt(Bigint.ZERO));
    }
}
