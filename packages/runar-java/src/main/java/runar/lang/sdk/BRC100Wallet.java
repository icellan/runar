package runar.lang.sdk;

/**
 * Minimal adapter interface for a BRC-100 compatible wallet. Parity with
 * the Go SDK's {@code WalletClient}; trimmed down to the subset the
 * {@link WalletProvider} needs to drive a deploy/call flow.
 *
 * <p>The Rúnar SDK never hands the wallet a raw unsigned transaction.
 * Instead, it computes the BIP-143 sighash locally (see
 * {@link RawTx#sighashBIP143}) and asks the wallet to sign the 32-byte
 * digest. The wallet is therefore only trusted to hold the private key
 * and produce a standard DER-encoded ECDSA signature — it never needs
 * to understand Rúnar locking-script semantics.
 *
 * <p>The {@code derivationPath} argument is an opaque string; it
 * corresponds to BRC-100's {@code keyID} + {@code protocolID}
 * tuple collapsed into a single namespace-safe token ({@code "1"},
 * {@code "runar/app/1"}, BIP-32 path, etc). Implementations MUST be
 * deterministic for a given path — successive calls return the same
 * public key and address.
 *
 * <p>Implementations must be thread-safe: the SDK may invoke
 * {@link #sign}, {@link #pubKey}, {@link #address} concurrently from
 * different threads.
 */
public interface BRC100Wallet {

    /**
     * Signs a 32-byte digest with the key at {@code derivationPath} and
     * returns a DER-encoded ECDSA signature (no sighash flag appended).
     * Must be low-S per BIP-62 / BSV consensus.
     *
     * @throws IllegalArgumentException if {@code sighash} is not 32 bytes
     */
    byte[] sign(byte[] sighash, String derivationPath);

    /**
     * Returns the 33-byte compressed secp256k1 public key at the given
     * derivation path.
     */
    byte[] pubKey(String derivationPath);

    /** Returns the BSV P2PKH address at the given derivation path. */
    String address(String derivationPath);
}
