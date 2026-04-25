package runar.examples.arithmetic;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * Arithmetic -- exercises every basic integer operator (+, -, *, /).
 *
 * <p>Stores a target value in the locking script and accepts two
 * operands; the unlock succeeds iff the sum of (a+b), (a-b), (a*b),
 * and (a/b) equals the stored target.
 */
class Arithmetic extends SmartContract {

    @Readonly Bigint target;

    Arithmetic(Bigint target) {
        super(target);
        this.target = target;
    }

    @Public
    void verify(Bigint a, Bigint b) {
        Bigint sum = a.plus(b);
        Bigint diff = a.minus(b);
        Bigint prod = a.times(b);
        Bigint quot = a.div(b);
        Bigint result = sum.plus(diff).plus(prod).plus(quot);
        assertThat(result.eq(this.target));
    }
}
