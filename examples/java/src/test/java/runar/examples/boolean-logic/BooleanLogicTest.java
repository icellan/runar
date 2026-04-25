package runar.examples.booleanlogic;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class BooleanLogicTest {

    @Test
    void contractInstantiates() {
        BooleanLogic c = new BooleanLogic(Bigint.of(10));
        assertNotNull(c);
        assertEquals(Bigint.of(10), c.threshold);
    }
}
