package runar.lang.sdk;

/**
 * Result of a BRC-100 {@code createAction}. Parity with the Go SDK's
 * {@code WalletActionResult}.
 *
 * @param txid  txid of the transaction the wallet built and broadcast
 * @param rawTx raw transaction hex, or {@code null} when the wallet does not
 *              return it
 */
public record WalletActionResult(String txid, String rawTx) {}
