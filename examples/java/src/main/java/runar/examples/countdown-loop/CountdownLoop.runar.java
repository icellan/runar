package runar.examples.countdownloop;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * CountdownLoop — Java port. {@code step = -1} (R-102).
 *
 * <p>The loop runs i = 5, 4, 3, 2, so {@code verify(seed)} asserts
 * {@code seed + 14}. See CountdownLoop.runar.ts for what the missing
 * descending fixture hid — a Move loop body dropped from the locking script
 * with no diagnostic, and a one-tier hex split on the Zig surface.
 */
class CountdownLoop extends SmartContract {

    @Readonly Bigint target;

    CountdownLoop(Bigint target) {
        super(target);
        this.target = target;
    }

    @Public
    void verify(Bigint seed) {
        Bigint acc = seed;
        for (Bigint i = Bigint.of(5); i.gt(Bigint.ONE); i = i.minus(Bigint.ONE)) {
            acc = acc.plus(i);
        }
        assertThat(acc.eq(this.target));
    }
}
