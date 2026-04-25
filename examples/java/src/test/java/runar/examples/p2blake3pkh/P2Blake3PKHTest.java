package runar.examples.p2blake3pkh;

import org.junit.jupiter.api.Test;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class P2Blake3PKHTest {

    @Test
    void contractInstantiates() {
        ByteString pkh = ByteString.fromHex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        P2Blake3PKH c = new P2Blake3PKH(pkh);
        assertNotNull(c);
        assertEquals(pkh, c.pubKeyHash);
    }
}
