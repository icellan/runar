package runar.examples.sphincswallet;

import org.junit.jupiter.api.Test;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link SPHINCSWallet}.
 *
 * <p>The {@code spend} method invokes
 * {@code verifySLHDSA_SHA2_128s}, which is not implemented in
 * {@link runar.lang.runtime.MockCrypto} (post-quantum verifications must
 * be tested via the compiler + VM path, not the simulator). End-to-end
 * conformance is exercised through the other compiler tiers via the
 * shared conformance suite.
 */
class SPHINCSWalletTest {

    @Test
    void contractInstantiates() {
        Addr ecdsaPubKeyHash = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        ByteString slhdsaPubKeyHash = ByteString.fromHex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4");
        SPHINCSWallet c = new SPHINCSWallet(ecdsaPubKeyHash, slhdsaPubKeyHash);
        assertNotNull(c);
        assertEquals(ecdsaPubKeyHash, c.ecdsaPubKeyHash);
        assertEquals(slhdsaPubKeyHash, c.slhdsaPubKeyHash);
    }
}
