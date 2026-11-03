// N-491: TS surface-parser operand anchor parity. A boolean identifier as the right operand of `<`.
// TS must anchor the refusal on this surface exactly where it does on .runar.ts
// (see n491-operand-anchor-surface-matrix.test.ts).
package runar.examples;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.abs;

class Anchor extends SmartContract {
    @Readonly Bigint t;

    Anchor(Bigint t) {
        super(t);
        this.t = t;
    }

    @Public
    void go(Bigint x, boolean flag) {
        assertThat(x < flag);
    }
}
