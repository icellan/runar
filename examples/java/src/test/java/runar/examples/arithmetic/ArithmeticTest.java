package runar.examples.arithmetic;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ArithmeticTest {

    @Test
    void contractInstantiates() {
        Arithmetic c = new Arithmetic(Bigint.of(42));
        assertNotNull(c);
        assertEquals(Bigint.of(42), c.target);
    }
}
