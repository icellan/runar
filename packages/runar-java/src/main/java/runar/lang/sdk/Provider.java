package runar.lang.sdk;

import java.util.List;

/**
 * Abstracts blockchain access for UTXO lookup and transaction broadcast.
 * Parity with {@code packages/runar-go/sdk_provider.go} {@code Provider}.
 *
 * <p>M8 scope exposes the minimum surface the deploy/call flow needs;
 * later milestones will extend with {@code getTransaction},
 * {@code getContractUtxo}, and fee-rate accessors.
 */
public interface Provider {

    /** Returns all spendable P2PKH UTXOs for the given address. */
    List<UTXO> listUtxos(String address);

    /** Broadcasts a raw hex-encoded transaction. Returns the txid. */
    String broadcastRaw(String txHex);

    /** Fetches a UTXO by outpoint, or returns {@code null} if unknown. */
    UTXO getUtxo(String txid, int vout);

    /** Fee rate in satoshis per KB (1000 bytes). BSV default is 100. */
    default long getFeeRate() {
        return 100L;
    }
}
