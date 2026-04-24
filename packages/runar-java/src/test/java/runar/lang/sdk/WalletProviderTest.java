package runar.lang.sdk;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WalletProviderTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    private static final String DEFAULT_PATH = "runar/m/0";

    // ------------------------------------------------------------------
    // Basic Signer surface: sign / pubKey / address route through wallet
    // ------------------------------------------------------------------

    @Test
    void signerOperationsRouteThroughWalletAtDefaultPath() throws Exception {
        LocalSigner inner = new LocalSigner(PRIV);
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(DEFAULT_PATH, inner);
        WalletProvider wp = new WalletProvider(wallet, new MockProvider(), DEFAULT_PATH);

        assertArrayEquals(inner.pubKey(), wp.pubKey());
        assertEquals(inner.address(), wp.address());

        byte[] digest = new byte[32];
        for (int i = 0; i < 32; i++) digest[i] = (byte) (0x30 + i);
        byte[] der = wp.sign(digest, null);

        // DER shape + verifies under the inner key.
        assertEquals(0x30, der[0] & 0xff);
        BigInteger[] rs = decodeDer(der);
        ECPoint pub = LocalSigner.DOMAIN.getCurve().decodePoint(inner.pubKey());
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(pub, LocalSigner.DOMAIN));
        assertTrue(verifier.verifySignature(digest, rs[0], rs[1]));

        // One call registered at the default path.
        assertEquals(1, wallet.signCount(DEFAULT_PATH));
    }

    @Test
    void signRejectsNon32ByteDigest() {
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(DEFAULT_PATH, new LocalSigner(PRIV));
        WalletProvider wp = new WalletProvider(wallet, new MockProvider(), DEFAULT_PATH);

        assertThrows(IllegalArgumentException.class, () -> wp.sign(new byte[16], null));
        assertThrows(IllegalArgumentException.class, () -> wp.sign(null, null));
    }

    // ------------------------------------------------------------------
    // Provider delegation — UTXO list + broadcast hit the inner provider
    // ------------------------------------------------------------------

    @Test
    void providerOperationsDelegateToInner() {
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(DEFAULT_PATH, new LocalSigner(PRIV));
        MockProvider inner = new MockProvider();
        inner.setFeeRate(250);
        UTXO u = new UTXO("ab".repeat(32), 0, 1_000L, ScriptUtils.buildP2PKHScript("00".repeat(20)));
        inner.addUtxo("addr1", u);

        WalletProvider wp = new WalletProvider(wallet, inner, DEFAULT_PATH);
        assertEquals(250, wp.getFeeRate());
        assertEquals(1, wp.listUtxos("addr1").size());
        assertSame(u, wp.getUtxo("ab".repeat(32), 0));

        String txid = wp.broadcastRaw("deadbeef");
        assertEquals(1, inner.getBroadcastedTxs().size());
        assertEquals("deadbeef", inner.getBroadcastedTxs().get(0));
        assertNotNull(txid);
    }

    // ------------------------------------------------------------------
    // Sighash parity: WalletProvider.computeSighash == RawTx.sighashBIP143
    // ------------------------------------------------------------------

    @Test
    void computeSighashMatchesRawTxSighashBIP143() {
        RawTx tx = new RawTx();
        tx.addInput("11".repeat(32), 3, "");
        tx.addOutput(999_000L, "76a914" + "00".repeat(20) + "88ac");
        String txHex = tx.toHex();
        String subscript = "76a914" + "22".repeat(20) + "88ac";

        byte[] direct = tx.sighashBIP143(0, subscript, 1_000_000L, RawTx.SIGHASH_ALL_FORKID);
        byte[] viaHelper = WalletProvider.computeSighash(txHex, 0, subscript, 1_000_000L);

        assertArrayEquals(direct, viaHelper);
    }

    // ------------------------------------------------------------------
    // Full call flow through WalletProvider mirrors the LocalSigner path
    // ------------------------------------------------------------------

    @Test
    void fullCallFlowMatchesLocalSignerPath() {
        LocalSigner inner = new LocalSigner(PRIV);
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(DEFAULT_PATH, inner);
        MockProvider provider = new MockProvider();
        WalletProvider wp = new WalletProvider(wallet, provider, DEFAULT_PATH);

        RunarArtifact artifact = PreparedCallTest.loadArtifact("artifacts/basic-p2pkh.runar.json");
        String pkhHex = HexFormat.of().formatHex(Hash160.hash160(inner.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));
        contract.setCurrentUtxo(new UTXO("ab".repeat(32), 0, 10_000L, contract.lockingScript()));

        // Prepare: pass WalletProvider as the signer so PubKey auto-fills.
        PreparedCall prepared = contract.prepareCall(
            "unlock", Arrays.asList(null, null), null, wp, wp
        );

        // Sign externally via the wallet (mirrors BRC-100 round-trip).
        byte[] der = wp.sign(prepared.sighashes().get(0), null);

        RunarContract.CallOutcome outcome = contract.finalizeCall(
            prepared, List.of(der), wp
        );

        assertNotNull(outcome.txid());
        assertEquals(1, provider.getBroadcastedTxs().size(),
            "broadcast must delegate to the inner provider");
        assertEquals(outcome.rawTxHex(), provider.getBroadcastedTxs().get(0));
        assertEquals(1, wallet.signCount(DEFAULT_PATH));
    }

    // ------------------------------------------------------------------
    // Key-derivation path is threaded through to sign / pubKey / address
    // ------------------------------------------------------------------

    @Test
    void derivationPathOverrideRoutesToAlternateKey() {
        LocalSigner k0 = new LocalSigner(PRIV);
        LocalSigner k1 = LocalSigner.random(new java.security.SecureRandom());

        MockBRC100Wallet wallet = new MockBRC100Wallet()
            .register("runar/m/0", k0)
            .register("runar/m/1", k1);

        WalletProvider wp = new WalletProvider(wallet, new MockProvider(), "runar/m/0");

        // Default path → k0
        assertArrayEquals(k0.pubKey(), wp.pubKey());
        assertEquals(k0.address(), wp.address());

        // Per-call override → k1
        assertArrayEquals(k1.pubKey(), wp.pubKey("runar/m/1"));
        assertEquals(k1.address(), wp.address("runar/m/1"));

        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 0x7f);

        byte[] sig0 = wp.sign(digest, null);            // default
        byte[] sig1 = wp.sign(digest, "runar/m/1");     // override

        // The two signatures must differ (different keys) but both verify.
        assertFalse(Arrays.equals(sig0, sig1));

        assertEquals(1, wallet.signCount("runar/m/0"));
        assertEquals(1, wallet.signCount("runar/m/1"));
    }

    @Test
    void unknownDerivationPathFailsLoudly() {
        MockBRC100Wallet wallet = new MockBRC100Wallet().register("runar/m/0", new LocalSigner(PRIV));
        WalletProvider wp = new WalletProvider(wallet, new MockProvider(), "runar/m/0");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> wp.sign(new byte[32], "runar/m/missing"));
        assertTrue(ex.getMessage().contains("runar/m/missing"), ex.getMessage());
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static BigInteger[] decodeDer(byte[] der) throws Exception {
        try (ASN1InputStream in = new ASN1InputStream(der)) {
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            return new BigInteger[] { r, s };
        }
    }
}
