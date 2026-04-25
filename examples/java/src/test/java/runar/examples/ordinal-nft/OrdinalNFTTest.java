package runar.examples.ordinalnft;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OrdinalNFTTest {

    private static final PubKey OWNER_PK = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey WRONG_PK = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");
    private static final Addr OWNER_HASH = MockCrypto.hash160(OWNER_PK);
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    @Test
    void contractInstantiates() {
        OrdinalNFT c = new OrdinalNFT(OWNER_HASH);
        assertNotNull(c);
        assertEquals(OWNER_HASH, c.pubKeyHash);
    }

    @Test
    void unlockAcceptsCorrectKey() {
        OrdinalNFT c = new OrdinalNFT(OWNER_HASH);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("unlock", SIG, OWNER_PK);
    }

    @Test
    void unlockRejectsWrongKey() {
        OrdinalNFT c = new OrdinalNFT(OWNER_HASH);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class, () -> sim.call("unlock", SIG, WRONG_PK));
    }
}
