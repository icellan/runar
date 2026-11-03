package runar.examples.shiftops;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * ShiftOps -- exercises bigint shift operators ({@code <<}, {@code >>}).
 * The caller supplies the expected results and the contract checks them;
 * see the TS source for the byte-array semantics of the shift opcodes.
 */
class ShiftOps extends SmartContract {

    @Readonly Bigint a;

    ShiftOps(Bigint a) {
        super(a);
        this.a = a;
    }

    @Public
    void testShift(Bigint expectedLeft, Bigint expectedRight) {
        Bigint left = this.a.shl(Bigint.of(3));
        Bigint right = this.a.shr(Bigint.of(2));
        assertThat(left.eq(expectedLeft));
        assertThat(right.eq(expectedRight));
    }
}
