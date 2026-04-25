package runar.examples.ecprimitives;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.MockCrypto;
import runar.lang.runtime.MockCrypto.Point;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ECPrimitivesTest {

    @Test
    void contractInstantiates() {
        Point pt = MockCrypto.ecMulGen(BigInteger.valueOf(7));
        ECPrimitives c = new ECPrimitives(pt);
        assertNotNull(c);
        assertEquals(pt, c.pt);
    }
}
