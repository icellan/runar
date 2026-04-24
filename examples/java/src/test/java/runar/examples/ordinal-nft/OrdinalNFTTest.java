package runar.examples.ordinalnft;

import org.junit.jupiter.api.Test;
import runar.lang.types.Addr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Phase 1 surface-level test: the {@link OrdinalNFT} contract must
 * compile against the runar-java SDK and instantiate with a fixed
 * Addr literal.
 *
 * <p>Runtime execution of {@code unlock(...)} requires the off-chain
 * simulator from M11; once that lands, add assertions that exercise
 * the method body with a valid {@code Sig} + {@code PubKey}.
 */
class OrdinalNFTTest {

    @Test
    void contractInstantiates() {
        Addr pkh = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        OrdinalNFT c = new OrdinalNFT(pkh);
        assertNotNull(c);
        assertEquals(pkh, c.pubKeyHash);
        // TODO(M11): once ContractSimulator is fully wired, exercise method bodies here
    }
}
