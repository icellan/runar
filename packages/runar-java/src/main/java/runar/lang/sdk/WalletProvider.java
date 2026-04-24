package runar.lang.sdk;

import java.util.List;

/**
 * {@link Provider} + {@link ExternalSigner} hybrid backed by a
 * {@link BRC100Wallet}. Parity with the Go SDK's {@code WalletProvider}
 * (see {@code packages/runar-go/sdk_wallet.go}).
 *
 * <p>The wallet <em>never</em> sees the unsigned transaction — the SDK
 * computes the BIP-143 sighash locally via {@link RawTx#sighashBIP143}
 * and hands only the 32-byte digest to {@link BRC100Wallet#sign}. This
 * matches BRC-100's split-capability design: the wallet can assert
 * "I signed hash X with key at path Y" without needing to parse Rúnar
 * locking scripts, stateful continuations, or OP_PUSHTX preambles.
 *
 * <p>UTXO lookup and transaction broadcast are delegated to an inner
 * {@link Provider}. BRC-100 wallets typically expose both signing and
 * a lightweight outpoint store; server-side Java code usually pairs
 * the wallet with an independent SV-Node / ARC broadcaster. The
 * split is explicit here so tests can pair a {@link MockBRC100Wallet}
 * with a {@link MockProvider}.
 *
 * <p>{@link Signer} operations (sign / pubKey / address) route through
 * the wallet using a configured default {@link #derivationPath}. Pass
 * a different path to {@link #sign(byte[], String)} to override — the
 * {@code derivationKey} parameter on {@link Signer#sign} is threaded
 * through unchanged.
 */
public final class WalletProvider implements Provider, ExternalSigner {

    private final BRC100Wallet wallet;
    private final Provider delegate;
    private final String derivationPath;

    /**
     * @param wallet         BRC-100 compatible signing backend
     * @param delegate       provider for UTXO lookup + broadcast
     * @param derivationPath default derivation path used by
     *                       {@link #pubKey()} / {@link #address()}
     *                       and by {@link #sign(byte[], String)} when
     *                       callers pass {@code null}
     */
    public WalletProvider(BRC100Wallet wallet, Provider delegate, String derivationPath) {
        if (wallet == null) {
            throw new IllegalArgumentException("WalletProvider: wallet is required");
        }
        if (delegate == null) {
            throw new IllegalArgumentException("WalletProvider: delegate provider is required");
        }
        if (derivationPath == null || derivationPath.isEmpty()) {
            throw new IllegalArgumentException("WalletProvider: derivationPath is required");
        }
        this.wallet = wallet;
        this.delegate = delegate;
        this.derivationPath = derivationPath;
    }

    public String derivationPath() {
        return derivationPath;
    }

    public BRC100Wallet wallet() {
        return wallet;
    }

    // ------------------------------------------------------------------
    // Provider
    // ------------------------------------------------------------------

    @Override
    public List<UTXO> listUtxos(String address) {
        return delegate.listUtxos(address);
    }

    @Override
    public String broadcastRaw(String txHex) {
        return delegate.broadcastRaw(txHex);
    }

    @Override
    public UTXO getUtxo(String txid, int vout) {
        return delegate.getUtxo(txid, vout);
    }

    @Override
    public long getFeeRate() {
        return delegate.getFeeRate();
    }

    // ------------------------------------------------------------------
    // Signer (delegated to BRC-100 wallet)
    // ------------------------------------------------------------------

    /**
     * Signs a BIP-143 sighash via the wallet. The {@code derivationKey}
     * argument overrides the provider's default path; pass {@code null}
     * to use {@link #derivationPath()}.
     *
     * <p>The returned value is the raw DER-encoded ECDSA signature
     * produced by the wallet — the caller appends the sighash flag
     * byte (or {@link RunarContract#finalizeCall} does so on its
     * behalf).
     */
    @Override
    public byte[] sign(byte[] sighash, String derivationKey) {
        if (sighash == null || sighash.length != 32) {
            throw new IllegalArgumentException(
                "WalletProvider.sign: sighash must be 32 bytes"
            );
        }
        String path = (derivationKey == null || derivationKey.isEmpty())
            ? derivationPath
            : derivationKey;
        byte[] der = wallet.sign(sighash, path);
        if (der == null || der.length < 2 || (der[0] & 0xff) != 0x30) {
            throw new IllegalStateException(
                "WalletProvider.sign: wallet returned a non-DER signature"
            );
        }
        return der;
    }

    @Override
    public byte[] pubKey() {
        return wallet.pubKey(derivationPath);
    }

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

    public String address(String derivationPath) {
        String path = (derivationPath == null || derivationPath.isEmpty())
            ? this.derivationPath
            : derivationPath;
        return wallet.address(path);
    }

    // ------------------------------------------------------------------
    // Sighash helper (local BIP-143 computation)
    // ------------------------------------------------------------------

    /**
     * Computes the BIP-143 sighash for an input of a prepared tx hex.
     * The wallet itself <em>does not</em> do this computation — it only
     * receives the resulting 32-byte digest. Callers that want to
     * inspect what the wallet will be asked to sign can call this
     * directly.
     *
     * @param txHex         raw tx hex (placeholder Sig slots allowed)
     * @param inputIndex    input position being signed
     * @param subscriptHex  locking script of the UTXO being spent
     *                      (or the post-codeseparator code portion for
     *                      stateful contracts)
     * @param inputSatoshis value of the UTXO being spent
     */
    public static byte[] computeSighash(
        String txHex,
        int inputIndex,
        String subscriptHex,
        long inputSatoshis
    ) {
        RawTx tx = RawTxParser.parse(txHex);
        return tx.sighashBIP143(inputIndex, subscriptHex, inputSatoshis, RawTx.SIGHASH_ALL_FORKID);
    }
}
