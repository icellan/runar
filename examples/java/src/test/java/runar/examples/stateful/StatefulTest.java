package runar.examples.stateful;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class StatefulTest {

    @Test
    void contractInstantiates() {
        Stateful c = new Stateful(Bigint.ZERO, Bigint.of(100));
        assertNotNull(c);
        assertEquals(Bigint.ZERO, c.count);
        assertEquals(Bigint.of(100), c.maxCount);
    }
}
