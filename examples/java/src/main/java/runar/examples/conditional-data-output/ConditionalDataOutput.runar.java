package runar.examples.conditionaldataoutput;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

/**
 * ConditionalDataOutput -- Audit regression: a stateful method that
 * emits a data output on a conditional branch must keep the canonical
 * single-output {@code computeStateOutput} state continuation on every
 * path.
 *
 * <p>See {@code conformance/tests/conditional-data-output-stateful/}
 * for the full rationale; the cross-format ports must produce identical
 * Bitcoin Script.
 */
class ConditionalDataOutput extends StatefulSmartContract {

    Bigint amount;

    ConditionalDataOutput(Bigint amount) {
        super(amount);
        this.amount = amount;
    }

    /**
     * The canonical bug: {@code addDataOutput} is wrapped in a branch.
     * The compiler must register the if's value as a DATA output ref
     * (not a state output ref) so that the parent method's continuation
     * hash keeps {@code computeStateOutput}.
     */
    @Public
    void pay(boolean flag, ByteString payload) {
        this.amount = this.amount.plus(Bigint.ONE);
        if (flag) {
            this.addDataOutput(0L, payload);
        }
        assertThat(true);
    }
}
