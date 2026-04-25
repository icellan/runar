package runar.examples.p384primitives;

import org.junit.jupiter.api.Test;
import runar.lang.types.P384Point;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class P384PrimitivesTest {

    // 96 bytes = x[48] || y[48]; arbitrary placeholder for instantiation.
    private static final P384Point EXPECTED = P384Point.fromHex("00".repeat(96));

    @Test
    void contractInstantiates() {
        P384Primitives c = new P384Primitives(EXPECTED);
        assertNotNull(c);
        assertEquals(EXPECTED, c.expectedPoint);
    }
}
