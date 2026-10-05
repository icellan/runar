// N-128: a `.runar.java` for-header whose update is a NON-UNIT step written
// as a compound assignment. Zig skipped the unrecognised `i += Bigint.TWO` as
// raw tokens and unrolled the loop with a unit step: two iterations over
// i = 0, 1 for a source loop that runs once (i = 0), byte-identical to the
// `i++` loop. Every tier must refuse it; TS, Go, Rust, Python, Ruby and Zig
// with:
//   For loop update must advance the loop variable by one ...
// (Java refuses the `+=` expression kind in its parser.)
package runar.examples.forstep;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

class ForStep extends StatefulSmartContract {

    Bigint count;

    ForStep(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment() {
        for (Bigint i = Bigint.ZERO; i.lt(Bigint.TWO); i += Bigint.TWO) {
            this.count = this.count.plus(Bigint.ONE);
        }
    }
}
