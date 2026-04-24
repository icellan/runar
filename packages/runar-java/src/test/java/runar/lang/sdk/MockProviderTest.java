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

    @Test
    void broadcastQueueRecordsHexAndReturnsDeterministicTxid() {
        MockProvider p = new MockProvider();
        String t1 = p.broadcastRaw("deadbeef");
        String t2 = p.broadcastRaw("deadbeef");
        assertEquals(2, p.getBroadcastedTxs().size());
        assertEquals("deadbeef", p.getBroadcastedTxs().get(0));
        assertEquals(64, t1.length());
        assertNotEquals(t1, t2, "broadcast counter ensures distinct txids for identical hex");
    }

    @Test
    void feeRateIsConfigurable() {
        MockProvider p = new MockProvider();
        assertEquals(100L, p.getFeeRate());
        p.setFeeRate(250L);
        assertEquals(250L, p.getFeeRate());
    }
}
