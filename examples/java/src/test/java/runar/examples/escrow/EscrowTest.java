package runar.examples.escrow;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Three-party escrow: release/refund both require two valid signatures.
 * The simulator's checkSig is permissive (always true on non-null sig+pk),
 * so the only failure modes are null sigs or wrong-length payloads.
 */
class EscrowTest {

    private static final String BUYER_PK   = "020000000000000000000000000000000000000000000000000000000000000001";
    private static final String SELLER_PK  = "020000000000000000000000000000000000000000000000000000000000000002";
    private static final String ARBITER_PK = "020000000000000000000000000000000000000000000000000000000000000003";
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

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
    }

    @Test
    void releaseAcceptsSellerAndArbiterSigs() {
        Escrow c = newContract();
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("release", SIG, SIG);
    }

    @Test
    void refundAcceptsBuyerAndArbiterSigs() {
        Escrow c = newContract();
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("refund", SIG, SIG);
    }

    @Test
    void releaseRejectsNullSig() {
        Escrow c = newContract();
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class, () -> sim.call("release", null, SIG));
        assertThrows(AssertionError.class, () -> sim.call("release", SIG, null));
    }

    @Test
    void refundRejectsNullSig() {
        Escrow c = newContract();
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class, () -> sim.call("refund", null, SIG));
        assertThrows(AssertionError.class, () -> sim.call("refund", SIG, null));
    }

    private static Escrow newContract() {
        return new Escrow(
            PubKey.fromHex(BUYER_PK),
            PubKey.fromHex(SELLER_PK),
            PubKey.fromHex(ARBITER_PK));
    }
}
