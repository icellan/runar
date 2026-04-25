package runar.examples.adddataoutput;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link DataOutputTest}. Mirrors
 * the conformance fixture; the broader simulator-driven test moved to
 * an example-suite test.
 */
class DataOutputTestTest {

    @Test
    void contractInstantiates() {
        DataOutputTest c = new DataOutputTest(Bigint.of(7));
        assertNotNull(c);
        assertEquals(Bigint.of(7), c.count);
    }
}
