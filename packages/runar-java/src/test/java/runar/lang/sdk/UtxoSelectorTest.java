package runar.lang.sdk;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UtxoSelectorTest {

    private static UTXO utxo(int index, long sats) {
        return new UTXO(String.format("%064x", index), 0, sats, "6a");
    }

    @Test
    void selectsSingleUtxoWhenFirstCoversTarget() {
        List<UTXO> picks = UtxoSelector.selectLargestFirst(
            List.of(utxo(1, 10_000L), utxo(2, 1_000L)),
            500L, 23, 100L
        );
        assertEquals(1, picks.size());
        assertEquals(10_000L, picks.get(0).satoshis());
    }

    @Test
    void selectsInLargestFirstOrder() {
        List<UTXO> picks = UtxoSelector.selectLargestFirst(
            List.of(utxo(1, 300L), utxo(2, 700L), utxo(3, 200L)),
            800L, 23, 100L
        );
        assertFalse(picks.isEmpty(), "should return something");
        // First pick must be the largest UTXO (700).
        assertEquals(700L, picks.get(0).satoshis());
        long total = picks.stream().mapToLong(UTXO::satoshis).sum();
        assertTrue(total >= 800L, "picks must cover target: " + total);
    }

    @Test
    void returnsAllWhenFundsAreInsufficient() {
        // Only 100 sats available; target 10000. Selector returns everything and
        // the deploy tx builder surfaces the real insufficient-funds error.
        List<UTXO> picks = UtxoSelector.selectLargestFirst(
            List.of(utxo(1, 50L), utxo(2, 50L)),
            10_000L, 23, 100L
        );
        assertEquals(2, picks.size());
    }
}
