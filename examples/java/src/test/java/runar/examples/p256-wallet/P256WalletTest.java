package runar.examples.p256wallet;

import org.junit.jupiter.api.Test;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class P256WalletTest {

    @Test
    void contractInstantiates() {
        Addr ecdsaPkh = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        ByteString p256Pkh = ByteString.fromHex("aabbccddeeff00112233445566778899aabbccdd");
        P256Wallet c = new P256Wallet(ecdsaPkh, p256Pkh);
        assertNotNull(c);
        assertEquals(ecdsaPkh, c.ecdsaPubKeyHash);
        assertEquals(p256Pkh, c.p256PubKeyHash);
    }
}
