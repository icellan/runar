// N-023 (R49): on the Java surface a bare name inside an instance method that
// no local or parameter shadows IS the field, so `count = ...` is a state
// write in Java. Pre-fix every tier lowered it as a local rebind instead: the
// stateful contract compiled with no update_prop and its state never changed.
// Every tier must refuse it with:
//   bare assignment to property 'count' is not allowed; write `this.count = ...`
// Shadowing is NOT refused: a local or a parameter named `count` makes the bare
// name a local, exactly as in Java.
package runar.examples.barecounter;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

class BareCounter extends StatefulSmartContract {

    Bigint count;

    BareCounter(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment() {
        count = count.plus(Bigint.ONE);
    }
}
