package runar.examples.p256primitives;

import org.junit.jupiter.api.Test;
import runar.lang.types.P256Point;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class P256PrimitivesTest {

    private static final P256Point EXPECTED = P256Point.fromHex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );

    @Test
    void contractInstantiates() {
        P256Primitives c = new P256Primitives(EXPECTED);
        assertNotNull(c);
        assertEquals(EXPECTED, c.expectedPoint);
    }
}
