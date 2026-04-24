package runar.lang.sdk;

/**
 * Abstracts private-key operations for signing transactions. Parity
 * with {@code packages/runar-go/sdk_signer.go} {@code Signer}.
 *
 * <p>{@link #sign(byte[], String)} signs a 32-byte BIP-143 sighash
 * digest. The {@code derivationKey} is an opaque identifier used by
 * wallet-backed signers (BRC-100, etc.) and ignored by single-key
 * implementations such as {@link LocalSigner}.
 */
public interface Signer {

    /** Returns DER-encoded ECDSA signature bytes (no sighash flag appended). */
    byte[] sign(byte[] sighash, String derivationKey);

    /** Returns the 33-byte compressed secp256k1 public key. */
    byte[] pubKey();

    /** Returns the BSV P2PKH address (mainnet Base58Check). */
    String address();
}
