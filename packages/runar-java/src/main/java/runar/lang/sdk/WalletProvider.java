package runar.lang.sdk;

import java.util.List;

/**
 * {@link Provider} + {@link Signer} hybrid backed by a
 * {@link BRC100Wallet}.
 *
 * <p><b>Relation to the Go SDK's {@code WalletProvider}</b>
 * ({@code packages/runar-go/sdk_wallet.go}). Shared: the BRC-100 action
 * surface — {@link #listWalletUtxos()} (Go {@code GetUtxos}: wallet
 * {@code listOutputs}, filtered to spendable outputs paying this key),
 * {@link #ensureFunding(long)} (Go {@code EnsureFunding}: wallet
 * {@code createAction}) and {@link RunarContract#deployWithWallet}
 * (Go {@code DeployWithWallet}). Different: the {@link Provider} methods
 * ({@link #listUtxos}, {@link #broadcastRaw}, {@link #getUtxo},
 * {@link #getFeeRate}) go to an inner delegate {@link Provider} rather than to
 * the wallet and an ARC / BSV Broadcaster endpoint, and there is no overlay
 * transaction lookup or raw-transaction cache.
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
public final class WalletProvider implements Provider, Signer {

    /** Default funding tag, as in Go's {@code WalletProviderOptions.FundingTag}. */
    public static final String DEFAULT_FUNDING_TAG = "funding";

    private final BRC100Wallet wallet;
    private final Provider delegate;
    private final String derivationPath;
    private final String basket;
    private final String fundingTag;

    /**
     * @param wallet         BRC-100 compatible signing backend
     * @param delegate       provider for UTXO lookup + broadcast
     * @param derivationPath default derivation path used by
     *                       {@link #pubKey()} / {@link #address()}
     *                       and by {@link #sign(byte[], String)} when
     *                       callers pass {@code null}
     */
    public WalletProvider(BRC100Wallet wallet, Provider delegate, String derivationPath) {
        this(wallet, delegate, derivationPath, "", null);
    }

    /**
     * @param basket     wallet basket for funding outputs and, by default,
     *                   {@link RunarContract#deployWithWallet} contract outputs
     *                   ({@code null} → empty, as in Go)
     * @param fundingTag tag marking funding outputs ({@code null}/empty →
     *                   {@value #DEFAULT_FUNDING_TAG})
     */
    public WalletProvider(
        BRC100Wallet wallet,
        Provider delegate,
        String derivationPath,
        String basket,
        String fundingTag
    ) {
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
        this.basket = basket == null ? "" : basket;
        this.fundingTag = (fundingTag == null || fundingTag.isEmpty()) ? DEFAULT_FUNDING_TAG : fundingTag;
    }

    /** Basket used for funding outputs and default wallet deploys. */
    public String basket() {
        return basket;
    }

    /** Tag marking this provider's funding outputs. */
    public String fundingTag() {
        return fundingTag;
    }

    // ------------------------------------------------------------------
    // BRC-100 action surface (GK-GAP-014; parity with Go GetUtxos /
    // EnsureFunding)
    // ------------------------------------------------------------------

    /**
     * Spendable P2PKH UTXOs the WALLET holds for this provider's key: BRC-100
     * {@code listOutputs(basket, [fundingTag], 100)}, keeping outputs that are
     * spendable, carry a locking script (N-043), and pay the P2PKH script of
     * {@link #pubKey()}. Parity with Go {@code WalletProvider.GetUtxos}.
     *
     * <p>This is the wallet's own view. {@link #listUtxos} still asks the
     * delegate provider (the chain), so existing deploy/call flows are
     * unchanged.
     *
     * @throws UnsupportedOperationException if the wallet has no
     *     {@code listOutputs}
     * @throws ProviderException if the wallet call fails
     */
    public List<UTXO> listWalletUtxos() {
        List<WalletOutput> outputs;
        try {
            outputs = wallet.listOutputs(basket, List.of(fundingTag), 100);
        } catch (UnsupportedOperationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new ProviderException("WalletProvider.listWalletUtxos: listing outputs: " + e.getMessage(), e);
        }
        String expected = ownP2pkhScript();
        List<UTXO> utxos = new java.util.ArrayList<>();
        for (WalletOutput out : outputs == null ? List.<WalletOutput>of() : outputs) {
            if (!out.spendable()) continue;
            String script = out.lockingScript();
            if (script == null || script.isEmpty()) continue;
            if (!script.equalsIgnoreCase(expected)) continue;
            String outpoint = out.outpoint() == null ? "" : out.outpoint();
            int dot = outpoint.lastIndexOf('.');
            if (dot <= 0) continue; // no usable outpoint: cannot be spent, drop (fail closed)
            int vout;
            try {
                vout = Integer.parseInt(outpoint.substring(dot + 1));
            } catch (NumberFormatException e) {
                continue;
            }
            utxos.add(new UTXO(outpoint.substring(0, dot), vout, out.satoshis(), script));
        }
        return utxos;
    }

    /**
     * Makes sure the wallet holds at least {@code minSatoshis} in spendable
     * outputs to this provider's key; when it does not, asks the wallet
     * ({@code createAction}) for ONE P2PKH output of {@code minSatoshis} to
     * {@link #address()}, in {@link #basket()} tagged {@link #fundingTag()}.
     * Parity with Go {@code WalletProvider.EnsureFunding}.
     *
     * @throws UnsupportedOperationException if the wallet has no action surface
     * @throws ProviderException if listing or creating the action fails
     */
    public void ensureFunding(long minSatoshis) {
        long total = 0;
        for (UTXO u : listWalletUtxos()) {
            total += u.satoshis();
        }
        if (total >= minSatoshis) {
            return;
        }
        WalletActionOutput funding = new WalletActionOutput(
            ScriptUtils.buildP2PKHScript(address()),
            minSatoshis,
            "funding for contract deployment",
            basket,
            List.of(fundingTag)
        );
        try {
            wallet.createAction("fund contract deployment", List.of(funding));
        } catch (UnsupportedOperationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new ProviderException(
                "WalletProvider.ensureFunding: creating funding action: " + e.getMessage(), e);
        }
    }

    private String ownP2pkhScript() {
        return "76a914" + java.util.HexFormat.of().formatHex(Hash160.hash160(pubKey())) + "88ac";
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
