// N-128: a `.runar.java` for-header whose update slot is a compound state
// write. Zig's parseForStmt recognised only `i = e`, `i++` and `i--` there
// and skipped anything else as raw tokens, so the update arrived as null and
// the validator read the C-style header as an implied-step surface. Zig alone
// compiled this (1416 hexchars) and silently DROPPED the per-iteration
// `this.count += 1` from the script. Every tier must refuse it; TS, Go, Rust,
// Python, Ruby and Zig with:
//   For loop update must advance the loop variable by one ...
// (Java refuses the `+=` expression kind in its parser.) The bare-name
// spelling `count += Bigint.ONE` is the same hole.
package runar.examples.forupdate;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

class ForUpdate extends StatefulSmartContract {

    Bigint count;

    ForUpdate(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment() {
        for (Bigint i = Bigint.ZERO; i.lt(Bigint.TWO); this.count += Bigint.ONE) {
            this.count = this.count.plus(Bigint.ONE);
        }
    }
}
