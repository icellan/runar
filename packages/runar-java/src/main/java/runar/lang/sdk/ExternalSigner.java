package runar.lang.sdk;

import java.util.Objects;

/**
 * Callback-based {@link Signer} that wraps a user-supplied signing
 * function with a fixed pubkey + address. Parity with the Go SDK's
 * {@code ExternalSigner} (see {@code packages/runar-go/sdk_signer.go}).
 *
 * <p>Use this when the actual signing happens in a wallet, HSM, remote
 * service, or any other process that owns the private key — the SDK
 * computes the BIP-143 sighash locally and hands the 32-byte digest
 * to the {@link SignCallback} for signature production. The pubkey
 * and address are fixed at construction time so tx-builders that need
 * them (UTXO lookup, change outputs, etc.) don't have to round-trip
 * to the external signer just to read identity bits.
 *
 * <p>The pubkey passed to the constructor is defensively copied; the
 * value returned by {@link #pubKey()} is also a fresh copy on every
 * call, so callers may freely mutate the returned array.
 */
public final class ExternalSigner implements Signer {

    /**
     * Functional interface for the signing callback. Receives the
     * 32-byte BIP-143 sighash digest and an opaque {@code derivationKey}
     * (typically a BRC-100 derivation path; may be {@code null} or
     * empty for single-key signers). Must return DER-encoded ECDSA
     * signature bytes <em>without</em> the trailing sighash flag byte —
     * the caller appends the flag when assembling the unlocking script.
     */
    @FunctionalInterface
    public interface SignCallback {
        byte[] sign(byte[] sighash, String derivationKey);
    }

    private final byte[] pubKey;
    private final String address;
    private final SignCallback signFn;

    /**
     * @param pubKey  33-byte compressed secp256k1 public key (defensively copied)
     * @param address BSV P2PKH address string (mainnet, testnet, or regtest)
     * @param signFn  callback invoked for every {@link #sign(byte[], String)} call
     * @throws NullPointerException if any argument is {@code null}
     */
    public ExternalSigner(byte[] pubKey, String address, SignCallback signFn) {
        Objects.requireNonNull(pubKey, "pubKey");
        Objects.requireNonNull(address, "address");
        Objects.requireNonNull(signFn, "signFn");
        this.pubKey = pubKey.clone();
        this.address = address;
        this.signFn = signFn;
    }

    @Override
    public byte[] sign(byte[] sighash, String derivationKey) {
        return signFn.sign(sighash, derivationKey);
    }

    @Override
    public byte[] pubKey() {
        return pubKey.clone();
    }

    @Override
    public String address() {
        return address;
    }
}
