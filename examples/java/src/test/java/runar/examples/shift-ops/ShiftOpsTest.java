package runar.examples.shiftops;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ShiftOpsTest {

    @Test
    void contractInstantiates() {
        ShiftOps c = new ShiftOps(Bigint.of(8));
        assertNotNull(c);
        assertEquals(Bigint.of(8), c.a);
    }
}
