package runar.lang.sdk;

/**
 * Unspent transaction output. Parity with
 * {@code packages/runar-go/sdk_types.go} {@code UTXO}.
 *
 * <p>{@code scriptHex} is the hex-encoded locking script of the UTXO.
 */
public record UTXO(String txid, int outputIndex, long satoshis, String scriptHex) {

    public UTXO {
        if (txid == null) throw new IllegalArgumentException("UTXO: txid is null");
        if (scriptHex == null) throw new IllegalArgumentException("UTXO: scriptHex is null");
        if (outputIndex < 0) throw new IllegalArgumentException("UTXO: outputIndex < 0");
        if (satoshis < 0) throw new IllegalArgumentException("UTXO: satoshis < 0");
    }
}
