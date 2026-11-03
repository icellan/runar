// N-244: the sighash marker glued to its flag list on the Java surface.
// Only .runar.ts honours the directive; every other surface must refuse ANY
// occurrence of the marker (N-039's rule), not just a word-bounded one, with
// the one shared "not supported by the Java surface parser" message.
// Before N-244 every tier read the glued form as prose and compiled ALL|FORKID.
package runar.examples.statefulcounter;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

class Counter extends StatefulSmartContract {

    Bigint count;

    Counter(Bigint count) {
        super(count);
        this.count = count;
    }

    /** @sighashSINGLE|FORKID */
    @Public
    void increment() {
        this.count = this.count.plus(Bigint.ONE);
    }
}
