package runar.examples.ifwithoutelse;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class IfWithoutElseTest {

    @Test
    void contractInstantiates() {
        IfWithoutElse c = new IfWithoutElse(Bigint.of(10));
        assertNotNull(c);
        assertEquals(Bigint.of(10), c.threshold);
    }
}
