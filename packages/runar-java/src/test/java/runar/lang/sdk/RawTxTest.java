package runar.lang.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Direct exercise of {@link RawTx} input/output accumulation, varint
 * widths, locktime, sequence overflow, and BIP-143 sighash edge cases.
 *
 * <p>{@link RawTx} is package-private; this test sits in the same
 * package to drive it directly without going through the higher-level
 * {@link TransactionBuilder}.
 */
class RawTxTest {

    private static final String TXID32 = "1100000000000000000000000000000000000000000000000000000000000022";
    private static final String P2PKH_SCRIPT = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";

    @Test
    void minimalSingleInputOutputRoundTrip() {
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "");
        tx.addOutput(50_000L, P2PKH_SCRIPT);
        String hex = tx.toHex();
        // Re-parse using RawTxParser and compare structural fields.
        RawTx parsed = RawTxParser.parse(hex);
        assertEquals(1, parsed.inputs.size());
        assertEquals(1, parsed.outputs.size());
        assertEquals(TXID32, parsed.inputs.get(0).prevTxid);
        assertEquals(0, parsed.inputs.get(0).prevVout);
        assertEquals(50_000L, parsed.outputs.get(0).satoshis);
        assertEquals(P2PKH_SCRIPT, parsed.outputs.get(0).scriptPubKeyHex);
    }

    @Test
    void multiInputAccumulationPreservesOrder() {
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "aa");
        tx.addInput(TXID32, 1, "bb");
        tx.addInput(TXID32, 2, "cc");
        tx.addOutput(1L, "00");
        String hex = tx.toHex();
        RawTx parsed = RawTxParser.parse(hex);
        assertEquals(3, parsed.inputs.size());
        assertEquals(0, parsed.inputs.get(0).prevVout);
        assertEquals(1, parsed.inputs.get(1).prevVout);
        assertEquals(2, parsed.inputs.get(2).prevVout);
        assertEquals("aa", parsed.inputs.get(0).scriptSigHex);
        assertEquals("bb", parsed.inputs.get(1).scriptSigHex);
        assertEquals("cc", parsed.inputs.get(2).scriptSigHex);
    }

    @Test
    void varintWidth1ByteBoundary252() {
        // 252 outputs → varint is still 1 byte (fcfc would be wrong; 252 = 0xfc which is the largest 1-byte varint)
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "");
        for (int i = 0; i < 252; i++) tx.addOutput(1L, "00");
        String hex = tx.toHex();
        RawTx parsed = RawTxParser.parse(hex);
        assertEquals(252, parsed.outputs.size());
    }

    @Test
    void varintWidth3ByteBoundary253() {
        // 253 outputs → varint is 3 bytes (0xfd + LE16).
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "");
        for (int i = 0; i < 253; i++) tx.addOutput(1L, "00");
        String hex = tx.toHex();
        RawTx parsed = RawTxParser.parse(hex);
        assertEquals(253, parsed.outputs.size());
    }

    @Test
    void locktimeRoundTrip() {
        RawTx tx = new RawTx();
        tx.locktime = 600_000;
        tx.addInput(TXID32, 0, "");
        tx.addOutput(0L, "00");
        String hex = tx.toHex();
        RawTx parsed = RawTxParser.parse(hex);
        assertEquals(600_000, parsed.locktime);
    }

    @Test
    void sequenceOverflowSerializedAsUnsigned() {
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "");
        tx.addOutput(1L, "00");
        tx.inputs.get(0).sequence = 0xffffffffL;
        String hex = tx.toHex();
        // After parse, sequence should round-trip as the unsigned value.
        RawTx parsed = RawTxParser.parse(hex);
        assertEquals(0xffffffffL, parsed.inputs.get(0).sequence);
    }

    @Test
    void scriptLengthAbove252UsesPushdataVarint() {
        // 256-byte script forces a 3-byte varint length prefix.
        StringBuilder script = new StringBuilder();
        for (int i = 0; i < 256; i++) script.append("ab");
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "");
        tx.addOutput(1L, script.toString());
        RawTx parsed = RawTxParser.parse(tx.toHex());
        assertEquals(script.toString(), parsed.outputs.get(0).scriptPubKeyHex);
    }

    @Test
    void bip143SighashIsDeterministic() {
        RawTx tx = newSimpleTx();
        byte[] h1 = tx.sighashBIP143(0, P2PKH_SCRIPT, 100_000L, RawTx.SIGHASH_ALL_FORKID);
        byte[] h2 = tx.sighashBIP143(0, P2PKH_SCRIPT, 100_000L, RawTx.SIGHASH_ALL_FORKID);
        assertArrayEquals(h1, h2);
        assertEquals(32, h1.length);
        // Sanity: hash must not be all zeros.
        boolean allZero = true;
        for (byte b : h1) if (b != 0) { allZero = false; break; }
        assertFalse(allZero, "sighash must not be all zeros");
    }

    @Test
    void bip143SighashChangesWithDifferentSatoshis() {
        RawTx tx = newSimpleTx();
        byte[] h1 = tx.sighashBIP143(0, P2PKH_SCRIPT, 100_000L, RawTx.SIGHASH_ALL_FORKID);
        byte[] h2 = tx.sighashBIP143(0, P2PKH_SCRIPT, 200_000L, RawTx.SIGHASH_ALL_FORKID);
        assertFalse(java.util.Arrays.equals(h1, h2), "sighash must depend on input satoshis");
    }

    @Test
    void bip143SighashChangesWithDifferentSubscript() {
        RawTx tx = newSimpleTx();
        byte[] h1 = tx.sighashBIP143(0, P2PKH_SCRIPT, 100_000L, RawTx.SIGHASH_ALL_FORKID);
        byte[] h2 = tx.sighashBIP143(0, "76aa", 100_000L, RawTx.SIGHASH_ALL_FORKID);
        assertFalse(java.util.Arrays.equals(h1, h2), "sighash must depend on subscript");
    }

    @Test
    void bip143SighashChangesWithDifferentInputIndex() {
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "");
        tx.addInput(TXID32, 1, "");
        tx.addOutput(1L, P2PKH_SCRIPT);
        byte[] h0 = tx.sighashBIP143(0, P2PKH_SCRIPT, 100_000L, RawTx.SIGHASH_ALL_FORKID);
        byte[] h1 = tx.sighashBIP143(1, P2PKH_SCRIPT, 100_000L, RawTx.SIGHASH_ALL_FORKID);
        assertFalse(java.util.Arrays.equals(h0, h1), "sighash must depend on which input is being signed");
    }

    @Test
    void setUnlockingScriptUpdatesIndividualInput() {
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "aa");
        tx.addInput(TXID32, 1, "bb");
        tx.setUnlockingScript(0, "11");
        assertEquals("11", tx.inputs.get(0).scriptSigHex);
        assertEquals("bb", tx.inputs.get(1).scriptSigHex);
    }

    @Test
    void setUnlockingScriptAcceptsNullForEmpty() {
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "aa");
        tx.setUnlockingScript(0, null);
        assertEquals("", tx.inputs.get(0).scriptSigHex);
    }

    private static RawTx newSimpleTx() {
        RawTx tx = new RawTx();
        tx.addInput(TXID32, 0, "");
        tx.addOutput(50_000L, P2PKH_SCRIPT);
        return tx;
    }
}
