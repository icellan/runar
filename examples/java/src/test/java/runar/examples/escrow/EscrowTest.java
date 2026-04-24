package runar.examples.escrow;

import org.junit.jupiter.api.Test;
import runar.lang.types.PubKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Phase 1 surface-level test: the {@link Escrow} contract must compile
 * against the runar-java SDK and instantiate with three fixed PubKey
 * literals.
 *
 * <p>Runtime execution of {@code release(...)} / {@code refund(...)}
 * requires the off-chain simulator from M11.
 */
class EscrowTest {

    private static final String BUYER_PK   = "020000000000000000000000000000000000000000000000000000000000000001";
    private static final String SELLER_PK  = "020000000000000000000000000000000000000000000000000000000000000002";
    private static final String ARBITER_PK = "020000000000000000000000000000000000000000000000000000000000000003";

    @Test
    void contractInstantiates() {
        PubKey buyer = PubKey.fromHex(BUYER_PK);
        PubKey seller = PubKey.fromHex(SELLER_PK);
        PubKey arbiter = PubKey.fromHex(ARBITER_PK);
        Escrow c = new Escrow(buyer, seller, arbiter);
        assertNotNull(c);
        assertEquals(buyer, c.buyer);
        assertEquals(seller, c.seller);
        assertEquals(arbiter, c.arbiter);
        // TODO(M11): once ContractSimulator is fully wired, exercise method bodies here
    }
}
