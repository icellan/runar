package runar.examples.bsv20token;

import org.junit.jupiter.api.Test;
import runar.lang.types.Addr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Phase 1 surface-level test: the {@link BSV20Token} contract must
 * compile against the runar-java SDK and instantiate with a fixed
 * Addr literal.
 */
class BSV20TokenTest {

    @Test
    void contractInstantiates() {
        Addr pkh = Addr.fromHex("1122334455667788990011223344556677889900");
        BSV20Token c = new BSV20Token(pkh);
        assertNotNull(c);
        assertEquals(pkh, c.pubKeyHash);
        // TODO(M11): once ContractSimulator is fully wired, exercise method bodies here
    }
}
