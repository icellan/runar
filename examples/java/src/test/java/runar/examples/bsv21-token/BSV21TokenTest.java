package runar.examples.bsv21token;

import org.junit.jupiter.api.Test;
import runar.lang.types.Addr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Phase 1 surface-level test: the {@link BSV21Token} contract must
 * compile against the runar-java SDK and instantiate with a fixed
 * Addr literal.
 */
class BSV21TokenTest {

    @Test
    void contractInstantiates() {
        Addr pkh = Addr.fromHex("aabbccddeeff00112233445566778899aabbccdd");
        BSV21Token c = new BSV21Token(pkh);
        assertNotNull(c);
        assertEquals(pkh, c.pubKeyHash);
        // TODO(M11): once ContractSimulator is fully wired, exercise method bodies here
    }
}
