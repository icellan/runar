package runar.examples.blake3;

import org.junit.jupiter.api.Test;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class Blake3TestTest {

    @Test
    void contractInstantiates() {
        ByteString expected = ByteString.fromHex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        Blake3Test c = new Blake3Test(expected);
        assertNotNull(c);
        assertEquals(expected, c.expected);
    }
}
