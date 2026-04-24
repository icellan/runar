package runar.lang.sdk;

import java.math.BigInteger;
import java.util.HexFormat;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LocalSignerTest {

    private static final String TEST_PRIVKEY =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    // Derived once via the same BouncyCastle pipeline and frozen as a
    // cross-implementation check: k*G for the key above.
    private static final String EXPECTED_COMPRESSED_PUB =
        "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";

    @Test
    void pubKeyMatchesSecp256k1Scalar() {
        LocalSigner s = new LocalSigner(TEST_PRIVKEY);
        assertEquals(EXPECTED_COMPRESSED_PUB, HexFormat.of().formatHex(s.pubKey()));
    }

    @Test
    void addressIsStandardBsvMainnetP2PKH() {
        LocalSigner s = new LocalSigner(TEST_PRIVKEY);
        String addr = s.address();
        // Mainnet P2PKH starts with "1" and is 26..35 chars.
        assertTrue(addr.startsWith("1"), "address should start with 1: " + addr);
        assertTrue(addr.length() >= 26 && addr.length() <= 35, "addr length: " + addr.length());
    }

    @Test
    void signProducesValidLowSEcdsaSignature() throws Exception {
        LocalSigner s = new LocalSigner(TEST_PRIVKEY);
        byte[] digest = new byte[32];
        for (int i = 0; i < 32; i++) digest[i] = (byte) (i + 1);

        byte[] der = s.sign(digest, null);
        BigInteger[] rs = decodeDer(der);
        BigInteger r = rs[0];
        BigInteger s1 = rs[1];

        BigInteger halfN = LocalSigner.DOMAIN.getN().shiftRight(1);
        assertTrue(s1.compareTo(halfN) <= 0, "signature must be low-S");

        // Verify with BouncyCastle against the recovered public key.
        ECPoint pub = LocalSigner.DOMAIN.getG().multiply(new BigInteger(1, HexFormat.of().parseHex(TEST_PRIVKEY))).normalize();
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(pub, LocalSigner.DOMAIN));
        assertTrue(verifier.verifySignature(digest, r, s1), "BouncyCastle verify must accept LocalSigner output");
    }

    @Test
    void signatureIsDeterministicAcrossCalls() {
        LocalSigner s = new LocalSigner(TEST_PRIVKEY);
        byte[] digest = new byte[32];
        byte[] a = s.sign(digest, null);
        byte[] b = s.sign(digest, null);
        assertArrayEquals(a, b, "RFC 6979 deterministic k → identical signatures");
    }

    @Test
    void rejectsMalformedPrivKey() {
        assertThrows(IllegalArgumentException.class, () -> new LocalSigner("00"));
        assertThrows(IllegalArgumentException.class, () -> new LocalSigner("zz".repeat(32)));
        assertThrows(IllegalArgumentException.class, () -> new LocalSigner("00".repeat(32))); // zero key
    }

    @Test
    void bip143SighashRoundTripsAgainstRawTx() {
        // Build a tiny tx with one P2PKH input and one output, compute the
        // BIP-143 sighash, and verify signing it with LocalSigner produces
        // a signature that BouncyCastle accepts under the signer's pubkey.
        LocalSigner s = new LocalSigner(TEST_PRIVKEY);

        RawTx tx = new RawTx();
        tx.addInput("ab".repeat(32), 0, "");
        tx.addOutput(500_000L, "76a914" + "00".repeat(20) + "88ac");
        String subscript = "76a914" + HexFormat.of().formatHex(Hash160.hash160(s.pubKey())) + "88ac";

        byte[] sighash = tx.sighashBIP143(0, subscript, 600_000L, RawTx.SIGHASH_ALL_FORKID);
        assertEquals(32, sighash.length);

        byte[] der = s.sign(sighash, null);
        BigInteger[] rs;
        try { rs = decodeDer(der); } catch (Exception e) { throw new AssertionError(e); }
        ECPoint pub = LocalSigner.DOMAIN.getCurve().decodePoint(s.pubKey());
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(pub, LocalSigner.DOMAIN));
        assertTrue(verifier.verifySignature(sighash, rs[0], rs[1]));
    }

    private static BigInteger[] decodeDer(byte[] der) throws Exception {
        try (ASN1InputStream in = new ASN1InputStream(der)) {
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            return new BigInteger[] { r, s };
        }
    }
}
