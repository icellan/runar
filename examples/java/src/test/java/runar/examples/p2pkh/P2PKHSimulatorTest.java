package runar.examples.p2pkh;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the M11 off-chain simulator against the real P2PKH contract
 * in {@code examples/java/src/main/java/runar/examples/p2pkh/}. The
 * contract's assertions rely on a matching hash160(pubKey) == pubKeyHash
 * check — real in the simulator since hashes are deterministic — and a
 * checkSig call (mocked to true). This test is the end-to-end proof
 * that a plain .runar.java contract runs natively in Java under the
 * simulator and fails/succeeds on the same conditions it would on-chain.
 */
class P2PKHSimulatorTest {

    private static final PubKey PK = PubKey.fromHex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );

    @Test
    void unlockSucceedsWithMatchingHash() {
        Addr h = MockCrypto.hash160(PK);
        P2PKH contract = new P2PKH(h);
        Sig s = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

        ContractSimulator sim = ContractSimulator.stateless(contract);
        assertDoesNotThrow(() -> sim.call("unlock", s, PK));
    }

    @Test
    void unlockFailsWhenHashDoesNotMatch() {
        Addr wrong = Addr.fromHex("00".repeat(20));
        P2PKH contract = new P2PKH(wrong);
        Sig s = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

        ContractSimulator sim = ContractSimulator.stateless(contract);
        assertThrows(AssertionError.class, () -> sim.call("unlock", s, PK));
    }
}
