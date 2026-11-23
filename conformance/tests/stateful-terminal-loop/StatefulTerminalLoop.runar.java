package runar.conformance.statefulterminalloop;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import static runar.lang.Builtins.assertThat;

/**
 * StatefulTerminalLoop -- a TERMINAL stateful method (no state write, so no
 * injected continuation assert) whose bounded loop of asserts is followed by
 * a final assert, which is the script result. Without it the method is
 * refused in every tier (conformance/negatives N547).
 */
class StatefulTerminalLoop extends StatefulSmartContract {

    Bigint floor;
    Bigint count;

    StatefulTerminalLoop(Bigint floor, Bigint count) {
        super(floor, count);
        this.floor = floor;
        this.count = count;
    }

    @Public
    void close(Bigint x) {
        for (Bigint i = Bigint.ZERO; i.lt(Bigint.of(2)); i = i.plus(Bigint.ONE)) {
            assertThat(x.ge(this.floor.plus(i)));
        }
        assertThat(x.gt(this.count));
    }
}
