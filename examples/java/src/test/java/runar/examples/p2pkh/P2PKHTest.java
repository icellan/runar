package runar.examples.p2pkh;

import org.junit.jupiter.api.Test;
import runar.lang.types.Addr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Phase 1 surface-level test: the {@link P2PKH} contract must compile
 * against the runar-java SDK. Real business-logic tests land in
 * milestone 11 once the off-chain simulator is available.
 */
class P2PKHTest {

    @Test
    void contractInstantiates() {
        Addr pkh = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        P2PKH c = new P2PKH(pkh);
        assertNotNull(c);
        assertEquals(pkh, c.pubKeyHash);
    }
}
