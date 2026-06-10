package runar.examples.covenantvault;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.Addr;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import runar.lang.types.SigHashPreimage;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CovenantVaultTest {

    private static final PubKey OWNER     = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final Addr   RECIPIENT = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
    private static final Sig    SIG       = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
    private static final Bigint MIN_AMOUNT = Bigint.of(1000);

    /** Build the canonical 34-byte P2PKH output: 8-byte LE amount ‖ 1976a914 ‖ pkh ‖ 88ac. */
    private static ByteString p2pkhOutput(Bigint amount, Addr pkh) {
        ByteString script = MockCrypto.cat(
            MockCrypto.cat(ByteString.fromHex("1976a914"), pkh),
            ByteString.fromHex("88ac")
        );
        return MockCrypto.cat(
            MockCrypto.num2bin(amount.value(), BigInteger.valueOf(8)),
            script
        );
    }

    /** Build a preimage whose first 32 bytes are hash256(outputs).
     *  The simulator's extractOutputHash echoes those bytes back. */
    private static SigHashPreimage preimageFor(ByteString outputs) {
        ByteString h = MockCrypto.hash256(outputs);
        return new SigHashPreimage(h.toByteArray());
    }

    private static CovenantVault newVault() {
        return new CovenantVault(OWNER, RECIPIENT, MIN_AMOUNT);
    }

    @Test
    void contractInstantiates() {
        CovenantVault c = newVault();
        assertNotNull(c);
        assertEquals(OWNER, c.owner);
        assertEquals(RECIPIENT, c.recipient);
        assertEquals(MIN_AMOUNT, c.minAmount);
    }

    @Test
    void spendSucceedsWithOwnerSignature() {
        ContractSimulator sim = ContractSimulator.stateless(newVault());
        ByteString expectedOutput = p2pkhOutput(MIN_AMOUNT, RECIPIENT);
        sim.call("spend", SIG, preimageFor(expectedOutput));
    }

    // -- Adversarial: wrong output count ------------------------------------

    @Test
    void spendRejectsZeroOutputs() {
        ContractSimulator sim = ContractSimulator.stateless(newVault());
        // hashOutputs commits to no outputs at all (n-1).
        SigHashPreimage preimage = preimageFor(ByteString.fromHex(""));
        assertThrows(AssertionError.class, () -> sim.call("spend", SIG, preimage));
    }

    @Test
    void spendRejectsExtraOutput() {
        ContractSimulator sim = ContractSimulator.stateless(newVault());
        ByteString required = p2pkhOutput(MIN_AMOUNT, RECIPIENT);
        Addr extraPkh = Addr.fromHex("cc".repeat(20));
        ByteString extra = p2pkhOutput(Bigint.of(500), extraPkh);
        SigHashPreimage preimage = preimageFor(MockCrypto.cat(required, extra));
        assertThrows(AssertionError.class, () -> sim.call("spend", SIG, preimage));
    }

    // -- Adversarial: swapped output order ----------------------------------

    @Test
    void spendRejectsReorderedOutputs() {
        ContractSimulator sim = ContractSimulator.stateless(newVault());
        ByteString required = p2pkhOutput(MIN_AMOUNT, RECIPIENT);
        Addr otherPkh = Addr.fromHex("cc".repeat(20));
        ByteString other = p2pkhOutput(MIN_AMOUNT, otherPkh);
        // Unauthorised output placed *before* the required one.
        SigHashPreimage preimage = preimageFor(MockCrypto.cat(other, required));
        assertThrows(AssertionError.class, () -> sim.call("spend", SIG, preimage));
    }

    // -- Adversarial: value at boundary -------------------------------------

    @Test
    void spendRejectsAmountMinusOne() {
        ContractSimulator sim = ContractSimulator.stateless(newVault());
        ByteString candidate = p2pkhOutput(Bigint.of(MIN_AMOUNT.value().longValue() - 1), RECIPIENT);
        SigHashPreimage preimage = preimageFor(candidate);
        assertThrows(AssertionError.class, () -> sim.call("spend", SIG, preimage));
    }

    @Test
    void spendRejectsAmountPlusOne() {
        ContractSimulator sim = ContractSimulator.stateless(newVault());
        ByteString candidate = p2pkhOutput(Bigint.of(MIN_AMOUNT.value().longValue() + 1), RECIPIENT);
        SigHashPreimage preimage = preimageFor(candidate);
        assertThrows(AssertionError.class, () -> sim.call("spend", SIG, preimage));
    }
}
