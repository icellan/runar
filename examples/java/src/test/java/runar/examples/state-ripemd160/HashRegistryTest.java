package runar.examples.stateripemd160;

import org.junit.jupiter.api.Test;
import runar.lang.types.Ripemd160;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class HashRegistryTest {

    @Test
    void contractInstantiates() {
        Ripemd160 h = Ripemd160.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        HashRegistry c = new HashRegistry(h);
        assertNotNull(c);
        assertEquals(h, c.currentHash);
    }
}
