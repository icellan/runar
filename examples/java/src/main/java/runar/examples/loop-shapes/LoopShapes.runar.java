package runar.examples.loopshapes;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * LoopShapes — Java port. A NON-ZERO loop start (R-102).
 *
 * The repository contained exactly two `for` loops before this example, both
 * zero-start and incrementing, so the ANF `loop` node's `start` field was never
 * exercised by any fixture. Go's constant folder dropped it (N-128) and stayed
 * green for that reason.
 */
class LoopShapes extends SmartContract {

    @Readonly Bigint target;

    LoopShapes(Bigint target) {
        super(target);
        this.target = target;
    }

    @Public
    void verify(Bigint seed) {
        Bigint acc = seed;
        for (Bigint i = Bigint.of(3); i.lt(Bigint.of(7)); i = i.plus(Bigint.ONE)) {
            acc = acc.plus(i);
        }
        assertThat(acc.eq(this.target));
    }
}
