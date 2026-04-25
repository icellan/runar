package runar.examples.shiftops;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * ShiftOps -- exercises bigint shift operators ({@code <<}, {@code >>}).
 * The asserts are tautological; the goal is to compile real shift
 * opcodes into the locking script.
 */
class ShiftOps extends SmartContract {

    @Readonly Bigint a;

    ShiftOps(Bigint a) {
        super(a);
        this.a = a;
    }

    @Public
    void testShift() {
        Bigint left = this.a.shl(Bigint.of(3));
        Bigint right = this.a.shr(Bigint.of(2));
        assertThat(left.ge(Bigint.ZERO) || left.lt(Bigint.ZERO));
        assertThat(right.ge(Bigint.ZERO) || right.lt(Bigint.ZERO));
    }
}
