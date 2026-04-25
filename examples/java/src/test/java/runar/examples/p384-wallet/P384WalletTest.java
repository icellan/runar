package runar.examples.p384wallet;

import org.junit.jupiter.api.Test;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class P384WalletTest {

    @Test
    void contractInstantiates() {
        Addr ecdsaPkh = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        ByteString p384Pkh = ByteString.fromHex("aabbccddeeff00112233445566778899aabbccdd");
        P384Wallet c = new P384Wallet(ecdsaPkh, p384Pkh);
        assertNotNull(c);
        assertEquals(ecdsaPkh, c.ecdsaPubKeyHash);
        assertEquals(p384Pkh, c.p384PubKeyHash);
    }
}
