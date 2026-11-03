package runar.examples.covenantvault;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.runtime.Preimage;
import runar.lang.sdk.SimulatedSpend;
import runar.lang.types.Addr;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import runar.lang.types.SigHashPreimage;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-099: spend's {@code checkPreimage(txPreimage)} is checked for real. Each
 * call runs inside a spending transaction the test describes (its outputs, and
 * the spender-chosen fields of a {@link Preimage} template); input 0 spends
 * CovenantVault's compiled locking script. The preimage passed is that
 * transaction's BIP-143 preimage ({@code spendPreimage}), so the adversarial
 * cases below are real transactions the covenant's output rule must reject,
 * not 32-byte stand-ins. Proves: the covenant accepts exactly the one-output
 * payment to the recipient, rejects every other transaction shape, and rejects
 * a preimage that is not the spending transaction's (a 32-byte fake, or the
 * preimage of a different transaction). Does NOT prove on-chain acceptance:
 * the honest preimage comes from the SDK's own sighash code, not a script VM.
 */
class CovenantVaultTest {

    private static final PubKey OWNER     = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final Addr   RECIPIENT = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
    private static final Sig    SIG       = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
    private static final Bigint MIN_AMOUNT = Bigint.of(1000);

    private static final Path SOURCE = Path.of(
        "src", "main", "java", "runar", "examples", "covenant-vault", "CovenantVault.runar.java"
    );

    /** Spender-chosen fields of every spend below (vault UTXO of 10000 sats). */
    private static final Preimage TEMPLATE = Preimage.builder().amount(BigInteger.valueOf(10000)).build();

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

    /** One output of the spending transaction: P2PKH to {@code pkh}. */
    private static SimulatedSpend.Out p2pkh(Bigint amount, Addr pkh) {
        return new SimulatedSpend.Out(amount.value().longValueExact(), "76a914" + pkh.toHex() + "88ac");
    }

    private static CovenantVault newVault() {
        return new CovenantVault(OWNER, RECIPIENT, MIN_AMOUNT);
    }

    private static ContractSimulator newSim() {
        return ContractSimulator.stateless(newVault(), SOURCE);
    }

    /**
     * Spend the vault in a transaction with {@code outputs}, passing that
     * transaction's own preimage, and require the covenant's output rule (not
     * checkPreimage) to reject it.
     */
    private static void assertCovenantRejects(List<SimulatedSpend.Out> outputs) {
        ContractSimulator sim = newSim();
        SigHashPreimage preimage = sim.spendPreimage("spend", TEMPLATE, outputs);
        AssertionError e = assertThrows(AssertionError.class,
            () -> sim.callWithSpend("spend", TEMPLATE, outputs, SIG, preimage));
        assertFalse(String.valueOf(e.getMessage()).startsWith("checkPreimage"),
            "rejected by the covenant's output rule, not by the preimage check: " + e.getMessage());
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
        ContractSimulator sim = newSim();
        List<SimulatedSpend.Out> outputs = List.of(p2pkh(MIN_AMOUNT, RECIPIENT));
        SigHashPreimage preimage = sim.spendPreimage("spend", TEMPLATE, outputs);
        // The preimage commits to the required output, serialized independently.
        assertArrayEquals(MockCrypto.hash256(p2pkhOutput(MIN_AMOUNT, RECIPIENT)).toByteArray(),
            Preimage.parse(preimage.toByteArray()).hashOutputs());
        sim.callWithSpend("spend", TEMPLATE, outputs, SIG, preimage);
    }

    // -- N-099: the preimage must be the spending transaction's -------------

    /** The 32-byte hash256(required output) the old tests passed as the preimage. */
    private static SigHashPreimage fake32() {
        return new SigHashPreimage(MockCrypto.hash256(p2pkhOutput(MIN_AMOUNT, RECIPIENT)).toByteArray());
    }

    @Test
    void spendRejectsA32ByteFakePreimage() {
        ContractSimulator sim = newSim();
        List<SimulatedSpend.Out> outputs = List.of(p2pkh(MIN_AMOUNT, RECIPIENT));
        AssertionError e = assertThrows(AssertionError.class,
            () -> sim.callWithSpend("spend", TEMPLATE, outputs, SIG, fake32()));
        assertTrue(e.getMessage().startsWith("checkPreimage"), e.getMessage());
    }

    /**
     * The preimage of a transaction that pays the recipient correctly, offered
     * for a transaction that pays someone else: well-formed, satisfies the
     * output rule, but signs a different transaction.
     */
    @Test
    void spendRejectsThePreimageOfADifferentTransaction() {
        ContractSimulator sim = newSim();
        SigHashPreimage honestElsewhere = sim.spendPreimage("spend", TEMPLATE, List.of(p2pkh(MIN_AMOUNT, RECIPIENT)));
        List<SimulatedSpend.Out> theft = List.of(p2pkh(MIN_AMOUNT, Addr.fromHex("cc".repeat(20))));
        AssertionError e = assertThrows(AssertionError.class,
            () -> sim.callWithSpend("spend", TEMPLATE, theft, SIG, honestElsewhere));
        assertTrue(e.getMessage().contains("hashOutputs"), e.getMessage());
    }

    /** Without a described spend there is nothing to check the preimage against: refuse, never pass. */
    @Test
    void spendWithoutASpendingTransactionRefuses() {
        ContractSimulator sim = ContractSimulator.stateless(newVault());
        assertThrows(IllegalStateException.class, () -> sim.call("spend", SIG, fake32()));
    }

    // -- Adversarial: wrong output count ------------------------------------

    @Test
    void spendRejectsZeroOutputs() {
        assertCovenantRejects(List.of());
    }

    @Test
    void spendRejectsExtraOutput() {
        assertCovenantRejects(List.of(
            p2pkh(MIN_AMOUNT, RECIPIENT),
            p2pkh(Bigint.of(500), Addr.fromHex("cc".repeat(20)))));
    }

    // -- Adversarial: swapped output order ----------------------------------

    @Test
    void spendRejectsReorderedOutputs() {
        // Unauthorised output placed *before* the required one.
        assertCovenantRejects(List.of(
            p2pkh(MIN_AMOUNT, Addr.fromHex("cc".repeat(20))),
            p2pkh(MIN_AMOUNT, RECIPIENT)));
    }

    // -- Adversarial: value at boundary -------------------------------------

    @Test
    void spendRejectsAmountMinusOne() {
        assertCovenantRejects(List.of(p2pkh(Bigint.of(MIN_AMOUNT.value().longValue() - 1), RECIPIENT)));
    }

    @Test
    void spendRejectsAmountPlusOne() {
        assertCovenantRejects(List.of(p2pkh(Bigint.of(MIN_AMOUNT.value().longValue() + 1), RECIPIENT)));
    }
}
