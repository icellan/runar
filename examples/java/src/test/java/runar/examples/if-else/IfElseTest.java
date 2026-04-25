package runar.examples.ifelse;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class IfElseTest {

    @Test
    void contractInstantiates() {
        IfElse c = new IfElse(Bigint.of(5));
        assertNotNull(c);
        assertEquals(Bigint.of(5), c.limit);
    }
}
