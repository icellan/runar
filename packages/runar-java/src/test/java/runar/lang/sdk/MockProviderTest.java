package runar.lang.sdk;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MockProviderTest {

    @Test
    void listUtxosRoundTripsInjectedEntries() {
        MockProvider p = new MockProvider();
        UTXO u1 = new UTXO("aa".repeat(32), 0, 1_000L, "76a914" + "00".repeat(20) + "88ac");
        UTXO u2 = new UTXO("bb".repeat(32), 1, 5_000L, "76a914" + "11".repeat(20) + "88ac");
        p.addUtxo("addrA", u1);
        p.addUtxo("addrA", u2);

        List<UTXO> got = p.listUtxos("addrA");
        assertEquals(2, got.size());
        assertEquals(u1, got.get(0));
        assertEquals(u2, got.get(1));
        assertTrue(p.listUtxos("absent").isEmpty());
    }

    @Test
    void getUtxoFindsByOutpoint() {
        MockProvider p = new MockProvider();
        UTXO u = new UTXO("cc".repeat(32), 2, 42L, "6a");
        p.addUtxo("addr", u);
        assertEquals(u, p.getUtxo("cc".repeat(32), 2));
        assertNull(p.getUtxo("dd".repeat(32), 2));
    }

    /**
     * Testing-gap remediation Phase A5: broadcastRaw is fail-closed by default,
     * so this bookkeeping test must hand it a REAL transaction whose spent
     * outpoint the provider knows. It previously broadcast the literal string
     * "deadbeef" — not a transaction at all — and asserted success.
     */
    @Test
    void broadcastQueueRecordsHexAndReturnsDeterministicTxid() {
        MockProvider p = new MockProvider();
        p.addKnownOutpoint("aa".repeat(32), 0, "51", 10_000L);
        RawTx tx = new RawTx();
        tx.addInput("aa".repeat(32), 0, "");
        tx.addOutput(9_000L, "51");
        String raw = tx.toHex();

        String t1 = p.broadcastRaw(raw);
        String t2 = p.broadcastRaw(raw);
        // Re-broadcasting the identical tx is idempotent, as on a node: a
        // second distinct txid would register its one real output twice.
        assertEquals(1, p.getBroadcastedTxs().size());
        assertEquals(raw, p.getBroadcastedTxs().get(0));
        assertEquals(64, t1.length());
        assertEquals(t1, t2, "an identical re-broadcast returns the first txid");
    }

    /** Fail-closed: a payload that is not a Bitcoin transaction is refused. */
    @Test
    void broadcastRefusesANonTransactionPayload() {
        MockProvider p = new MockProvider();
        assertThrows(BroadcastRejectedException.class, () -> p.broadcastRaw("deadbeef"));
    }

    @Test
    void feeRateIsConfigurable() {
        MockProvider p = new MockProvider();
        assertEquals(100L, p.getFeeRate());
        p.setFeeRate(250L);
        assertEquals(250L, p.getFeeRate());
    }
}
