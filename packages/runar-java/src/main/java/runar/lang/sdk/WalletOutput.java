package runar.lang.sdk;

/**
 * A wallet-held output as reported by BRC-100 {@code listOutputs}. Parity with
 * the Go SDK's {@code WalletOutput}.
 *
 * @param satoshis      output value
 * @param lockingScript locking script hex (may be empty when the wallet did not
 *                      include it; such outputs are never treated as spendable
 *                      UTXOs — N-043)
 * @param spendable     whether the wallet considers the output spendable
 * @param outpoint      {@code "<txid>.<vout>"}
 */
public record WalletOutput(long satoshis, String lockingScript, boolean spendable, String outpoint) {}
