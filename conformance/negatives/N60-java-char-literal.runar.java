// F-011 (folded in): a Java char literal. Go skipped char literals up to the
// next single quote without a diagnostic, so the guard on the next line
// vanished and @bsv/sdk Spend.validate accepted the Go artifact with y = 100.
// Every hand-written Java surface must refuse with:
//   char literals are unsupported in Rúnar Java contracts
package runar.examples.guarded;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Guarded extends SmartContract {
    Guarded() {
        super();
    }

    @Public
    void unlock(Bigint y) {
        Bigint z = y; 'c
        assertThat(y.lt(Bigint.of(5)));
        // ';
        assertThat(z.ge(Bigint.ZERO));
    }
}
