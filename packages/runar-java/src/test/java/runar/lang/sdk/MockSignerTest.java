package runar.lang.sdk;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MockSignerTest {

    @Test
    void defaultsMatchGoMockSignerShape() {
        MockSigner s = new MockSigner();
        byte[] pk = s.pubKey();
        assertEquals(33, pk.length);
        assertEquals(0x02, pk[0] & 0xff);
        for (int i = 1; i < 33; i++) assertEquals(0, pk[i]);
        assertEquals("0".repeat(40), s.address());
    }

    @Test
    void signReturnsDeterministicPlaceholder() {
        MockSigner s = new MockSigner();
        byte[] sig1 = s.sign(new byte[32], null);
        byte[] sig2 = s.sign(new byte[32], null);
        assertArrayEquals(sig1, sig2);
        assertEquals(71, sig1.length);
        assertEquals(0x30, sig1[0] & 0xff);
    }

    @Test
    void customPubKeyAndAddressAreReturnedVerbatim() {
        byte[] pk = HexFormat.of().parseHex("02" + "11".repeat(32));
        MockSigner s = new MockSigner(pk, "mockAddr");
        assertArrayEquals(pk, s.pubKey());
        assertEquals("mockAddr", s.address());
    }
}
