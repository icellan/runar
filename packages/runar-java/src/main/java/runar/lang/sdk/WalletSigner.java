package runar.lang.sdk;

/**
 * {@link Signer} backed by a {@link BRC100Wallet}. Parity with the
 * {@code WalletSigner} class shipped by the TypeScript, Go, Rust,
 * Python, Zig, and Ruby SDKs.
 *
 * <p>This is the standalone signing half of {@link WalletProvider}: where
 * {@code WalletProvider} bundles a BRC-100 wallet with an inner
 * {@link Provider} for UTXO lookup + broadcast, {@code WalletSigner} wraps
 * only the wallet and exposes the {@link Signer} surface. Use it when the
 * signing backend and the chain-access backend are separate — e.g. a
 * BRC-100 wallet for keys paired with an independent SV-Node / ARC
 * provider.
 *
 * <p>The wallet never sees the unsigned transaction: callers compute the
 * BIP-143 sighash locally (via {@link RawTx#sighashBIP143}) and hand only
 * the 32-byte digest to {@link #sign}.
 *
 * <p>Thread-safety follows {@link BRC100Wallet}'s contract — the SDK may
 * invoke {@link #sign}, {@link #pubKey}, {@link #address} concurrently.
 */
public final class WalletSigner implements Signer {

    private final BRC100Wallet wallet;
    private final String derivationPath;

    /**
     * @param wallet         BRC-100 compatible signing backend
     * @param derivationPath default derivation path used by {@link #pubKey()}
     *                       / {@link #address()} and by {@link #sign} when
     *                       callers pass a {@code null}/empty derivation key
     */
    public WalletSigner(BRC100Wallet wallet, String derivationPath) {
        if (wallet == null) {
            throw new IllegalArgumentException("WalletSigner: wallet is required");
        }
        if (derivationPath == null || derivationPath.isEmpty()) {
            throw new IllegalArgumentException("WalletSigner: derivationPath is required");
        }
        this.wallet = wallet;
        this.derivationPath = derivationPath;
    }

    /** The default derivation path used when callers pass no override. */
    public String derivationPath() {
        return derivationPath;
    }

    /** The underlying BRC-100 wallet. */
    public BRC100Wallet wallet() {
        return wallet;
    }

    /**
     * Signs a 32-byte BIP-143 sighash via the wallet. The
     * {@code derivationKey} argument overrides the signer's default path;
     * pass {@code null} or an empty string to use {@link #derivationPath()}.
     *
     * @return the raw DER-encoded ECDSA signature (no sighash flag byte)
     */
    @Override
    public byte[] sign(byte[] sighash, String derivationKey) {
        if (sighash == null || sighash.length != 32) {
            throw new IllegalArgumentException(
                "WalletSigner.sign: sighash must be 32 bytes"
            );
        }
        String path = (derivationKey == null || derivationKey.isEmpty())
            ? derivationPath
            : derivationKey;
        byte[] der = wallet.sign(sighash, path);
        if (der == null || der.length < 2 || (der[0] & 0xff) != 0x30) {
            throw new IllegalStateException(
                "WalletSigner.sign: wallet returned a non-DER signature"
            );
        }
        return der;
    }

    @Override
    public byte[] pubKey() {
        return wallet.pubKey(derivationPath);
    }

    /**
     * Returns the 33-byte compressed public key at {@code derivationPath},
     * or the signer's default path when {@code null}/empty.
     */
    public byte[] pubKey(String derivationPath) {
        String path = (derivationPath == null || derivationPath.isEmpty())
            ? this.derivationPath
            : derivationPath;
        return wallet.pubKey(path);
    }

    @Override
    public String address() {
        return wallet.address(derivationPath);
    }
}
