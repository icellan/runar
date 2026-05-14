package runar.lang.sdk;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link WalletSigner} — the standalone {@link Signer} backed by a
 * {@link BRC100Wallet}, added under GAP-m7 for cross-tier API symmetry with
 * the {@code WalletSigner} class in the other 6 SDK tiers.
 */
class WalletSignerTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    private static final String DEFAULT_PATH = "runar/m/0";
    private static final String ALT_PATH = "runar/m/1";

    // ------------------------------------------------------------------
    // Signer surface routes through the wallet at the default path
    // ------------------------------------------------------------------

    @Test
    void signerOperationsRouteThroughWalletAtDefaultPath() throws Exception {
        LocalSigner inner = new LocalSigner(PRIV);
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(DEFAULT_PATH, inner);
        WalletSigner ws = new WalletSigner(wallet, DEFAULT_PATH);

        assertArrayEquals(inner.pubKey(), ws.pubKey());
        assertEquals(inner.address(), ws.address());
        assertEquals(DEFAULT_PATH, ws.derivationPath());
        assertSame(wallet, ws.wallet());

        byte[] digest = digest32();
        byte[] der = ws.sign(digest, null);

        assertEquals(0x30, der[0] & 0xff, "signature must be DER-encoded");
        assertTrue(verifies(der, digest, inner.pubKey()),
            "signature must verify under the wallet's key at the default path");
    }

    // ------------------------------------------------------------------
    // A non-null derivationKey overrides the default path
    // ------------------------------------------------------------------

    @Test
    void derivationKeyOverridesDefaultPath() throws Exception {
        LocalSigner def = new LocalSigner(PRIV);
        LocalSigner alt = LocalSigner.random(new java.security.SecureRandom());
        MockBRC100Wallet wallet = new MockBRC100Wallet()
            .register(DEFAULT_PATH, def)
            .register(ALT_PATH, alt);
        WalletSigner ws = new WalletSigner(wallet, DEFAULT_PATH);

        byte[] digest = digest32();
        byte[] der = ws.sign(digest, ALT_PATH);

        assertTrue(verifies(der, digest, alt.pubKey()),
            "explicit derivationKey must route to the ALT path key");
        assertEquals(1, wallet.signCount(ALT_PATH));
        assertEquals(0, wallet.signCount(DEFAULT_PATH));
        assertArrayEquals(alt.pubKey(), ws.pubKey(ALT_PATH));
    }

    // ------------------------------------------------------------------
    // Constructor + input validation
    // ------------------------------------------------------------------

    @Test
    void constructorRejectsNullWalletAndEmptyPath() {
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(DEFAULT_PATH, new LocalSigner(PRIV));
        assertThrows(IllegalArgumentException.class, () -> new WalletSigner(null, DEFAULT_PATH));
        assertThrows(IllegalArgumentException.class, () -> new WalletSigner(wallet, null));
        assertThrows(IllegalArgumentException.class, () -> new WalletSigner(wallet, ""));
    }

    @Test
    void signRejectsNon32ByteSighash() {
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(DEFAULT_PATH, new LocalSigner(PRIV));
        WalletSigner ws = new WalletSigner(wallet, DEFAULT_PATH);
        assertThrows(IllegalArgumentException.class, () -> ws.sign(new byte[31], null));
        assertThrows(IllegalArgumentException.class, () -> ws.sign(new byte[33], null));
        assertThrows(IllegalArgumentException.class, () -> ws.sign(null, null));
    }

    @Test
    void emptyDerivationKeyFallsBackToDefaultPath() throws Exception {
        LocalSigner inner = new LocalSigner(PRIV);
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(DEFAULT_PATH, inner);
        WalletSigner ws = new WalletSigner(wallet, DEFAULT_PATH);

        byte[] digest = digest32();
        byte[] der = ws.sign(digest, "");
        assertTrue(verifies(der, digest, inner.pubKey()));
        assertEquals(1, wallet.signCount(DEFAULT_PATH));
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static byte[] digest32() {
        byte[] d = new byte[32];
        for (int i = 0; i < 32; i++) d[i] = (byte) (0x30 + i);
        return d;
    }

    private static boolean verifies(byte[] der, byte[] digest, byte[] pubKey) throws Exception {
        BigInteger[] rs = decodeDer(der);
        ECPoint pub = LocalSigner.DOMAIN.getCurve().decodePoint(pubKey);
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(pub, LocalSigner.DOMAIN));
        return verifier.verifySignature(digest, rs[0], rs[1]);
    }

    private static BigInteger[] decodeDer(byte[] der) throws Exception {
        try (ASN1InputStream in = new ASN1InputStream(der)) {
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            return new BigInteger[] {
                ((ASN1Integer) seq.getObjectAt(0)).getValue(),
                ((ASN1Integer) seq.getObjectAt(1)).getValue(),
            };
        }
    }
}
