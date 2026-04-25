package runar.examples.propertyinitializers;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PropertyInitializersTest {

    @Test
    void contractInstantiatesWithDefaults() {
        PropertyInitializers c = new PropertyInitializers(Bigint.of(100));
        assertNotNull(c);
        assertEquals(Bigint.of(100), c.maxCount);
        assertEquals(Bigint.ZERO, c.count);
        assertTrue(c.active);
    }
}
