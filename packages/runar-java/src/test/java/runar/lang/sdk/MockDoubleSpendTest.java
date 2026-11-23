package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * MockProvider must refuse a double spend: a second, DIFFERENT transaction
 * spending an outpoint an earlier accepted broadcast already spent. A node
 * refuses it, so acking it lets a test "succeed" at a spend the network
 * rejects.
 */
class MockDoubleSpendTest {

    private static final String OP_TRUE = "51";
    private static final String FUND = "ab".repeat(32);

    private static String tx(long outSats, String... prevTxids) {
        RawTx tx = new RawTx();
        for (String prev : prevTxids) tx.addInput(prev, 0, "");
        tx.addOutput(outSats, OP_TRUE);
        return tx.toHex();
    }

    /** Deploy: broadcast a tx creating an OP_TRUE output; returns its txid. */
    private static String deploy(MockProvider p) {
        p.addKnownOutpoint(FUND, 0, OP_TRUE, 10_000L);
        return p.broadcastRaw(tx(9_000L, FUND));
    }

    @Test
    void refusesADifferentTxSpendingAnAlreadySpentOutpoint() {
        MockProvider p = new MockProvider();
        String d = deploy(p);
        String first = tx(8_000L, d);
        p.broadcastRaw(first);
        String conflicting = tx(7_000L, d);
        assertNotEquals(first, conflicting);
        int before = p.getBroadcastedTxs().size();
        BroadcastRejectedException e = assertThrows(BroadcastRejectedException.class, () -> p.broadcastRaw(conflicting));
        assertTrue(e.getMessage().contains("already spent"), e.getMessage());
        assertEquals(MockProvider.RejectionReason.DOUBLE_SPEND, p.lastRejection());
        assertEquals(before, p.getBroadcastedTxs().size());
    }

    @Test
    void refusesATxSpendingOneOutpointTwice() {
        MockProvider p = new MockProvider();
        String d = deploy(p);
        BroadcastRejectedException e = assertThrows(BroadcastRejectedException.class, () -> p.broadcastRaw(tx(8_000L, d, d)));
        assertTrue(e.getMessage().contains("more than once"), e.getMessage());
    }

    @Test
    void listUtxosOmitsAnOutpointAnAcceptedBroadcastSpent() {
        MockProvider p = new MockProvider();
        p.addUtxo("funder", new UTXO(FUND, 0, 10_000L, OP_TRUE));
        p.addUtxo("funder", new UTXO(FUND, 1, 5_000L, OP_TRUE));
        p.broadcastRaw(tx(9_000L, FUND));
        assertEquals(java.util.List.of(1),
            p.listUtxos("funder").stream().map(UTXO::outputIndex).toList());
    }

    @Test
    void listUtxosListsANewP2pkhOutputUnderTheAddressItPays() {
        MockProvider p = new MockProvider();
        String pkh = "1111111111111111111111111111111111111111";
        p.addUtxo(pkh, new UTXO("cd".repeat(32), 0, 1L, OP_TRUE));
        p.addKnownOutpoint(FUND, 0, OP_TRUE, 10_000L);
        RawTx t = new RawTx();
        t.addInput(FUND, 0, "");
        t.addOutput(9_000L, "76a914111111111111111111111111111111111111111188ac");
        String txid = p.broadcastRaw(t.toHex());
        assertEquals(java.util.List.of(new UTXO(txid, 0, 9_000L, "76a914111111111111111111111111111111111111111188ac")),
            p.listUtxos(pkh).stream().filter(u -> u.txid().equals(txid)).toList());
    }

    @Test
    void aRefusedBroadcastDoesNotSpendItsInputs() {
        MockProvider p = new MockProvider();
        String d = deploy(p);
        assertThrows(BroadcastRejectedException.class, () -> p.broadcastRaw(tx(50_000L, d)));
        assertDoesNotThrow(() -> p.broadcastRaw(tx(8_000L, d)));
    }

    @Test
    void identicalRebroadcastIsNotADoubleSpend() {
        MockProvider p = new MockProvider();
        String d = deploy(p);
        String t = tx(8_000L, d);
        String first = p.broadcastRaw(t);
        int before = p.getBroadcastedTxs().size();
        assertEquals(first, assertDoesNotThrow(() -> p.broadcastRaw(t)));
        assertEquals(before, p.getBroadcastedTxs().size());
    }
}
