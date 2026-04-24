package runar.lang.sdk;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Largest-first UTXO selection with fee-aware iteration. Parity with
 * Go {@code SelectUtxos} in {@code packages/runar-go/sdk_deployment.go}.
 *
 * <p>Sorts the provided UTXO set descending by satoshi value, then
 * greedily accumulates until the running total covers
 * {@code targetSatoshis + estimatedFee(selectedCount, scriptLen, feeRate)}.
 */
public final class UtxoSelector {
    private UtxoSelector() {}

    /**
     * Selects UTXOs large-first to fund a target amount including
     * dynamically-estimated fees for the deployment tx.
     *
     * <p>Returns every UTXO if the total is still short — the caller
     * (transaction builder) produces the definitive insufficient-funds
     * error with real fee numbers.
     */
    public static List<UTXO> selectLargestFirst(
        List<UTXO> utxos,
        long targetSatoshis,
        int lockingScriptByteLen,
        long feeRate
    ) {
        List<UTXO> sorted = new ArrayList<>(utxos);
        sorted.sort(Comparator.comparingLong(UTXO::satoshis).reversed());

        List<UTXO> selected = new ArrayList<>();
        long total = 0;

        for (UTXO u : sorted) {
            selected.add(u);
            total += u.satoshis();
            long fee = FeeEstimator.estimateDeployFee(selected.size(), lockingScriptByteLen, feeRate);
            if (total >= targetSatoshis + fee) {
                return selected;
            }
        }
        return selected;
    }
}
