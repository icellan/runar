package runar.examples.privatehelperoutputs;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link PrivateHelperOutputs}.
 * The simulator-driven cross-compiler test runs from the
 * example-suite harness; this just confirms the contract
 * construction and field bindings line up.
 */
class PrivateHelperOutputsTest {

    @Test
    void contractInstantiates() {
        PrivateHelperOutputs c = new PrivateHelperOutputs(Bigint.of(7));
        assertNotNull(c);
        assertEquals(Bigint.of(7), c.counter);
    }
}
