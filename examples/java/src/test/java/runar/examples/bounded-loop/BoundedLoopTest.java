package runar.examples.boundedloop;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class BoundedLoopTest {

    @Test
    void contractInstantiates() {
        BoundedLoop c = new BoundedLoop(Bigint.of(20));
        assertNotNull(c);
        assertEquals(Bigint.of(20), c.expectedSum);
    }
}
