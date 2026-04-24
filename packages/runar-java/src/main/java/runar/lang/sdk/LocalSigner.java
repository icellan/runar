package runar.lang.sdk;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HexFormat;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECPoint;

/**
 * In-memory {@link Signer} backed by BouncyCastle. Parity with
 * {@code packages/runar-go/sdk_signer.go} {@code LocalSigner}.
 *
 * <p>Private key is a 32-byte hex string (64 hex chars) — WIF import
 * is not covered in M8 (see M9). The signer produces a deterministic
 * ECDSA signature per RFC 6979 with low-S normalisation.
 */
public final class LocalSigner implements Signer {

    private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256k1");
    static final ECDomainParameters DOMAIN = new ECDomainParameters(
        CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH()
    );
    private static final BigInteger HALF_N = CURVE.getN().shiftRight(1);

    private final BigInteger privKey;
    private final byte[] compressedPubKey;
    private final String address;

    public LocalSigner(String privKeyHex) {
        if (privKeyHex == null || !privKeyHex.matches("^[0-9a-fA-F]{64}$")) {
            throw new IllegalArgumentException(
                "LocalSigner: expected a 64-char hex private key"
            );
        }
        this.privKey = new BigInteger(1, HexFormat.of().parseHex(privKeyHex));
        if (privKey.signum() <= 0 || privKey.compareTo(CURVE.getN()) >= 0) {
            throw new IllegalArgumentException("LocalSigner: private key out of range");
        }
        ECPoint pub = CURVE.getG().multiply(privKey).normalize();
        this.compressedPubKey = pub.getEncoded(true);
        this.address = Base58Check.encodeMainnetP2PKH(Hash160.hash160(compressedPubKey));
    }

    public static LocalSigner random(SecureRandom rng) {
        byte[] buf = new byte[32];
        BigInteger n = CURVE.getN();
        BigInteger d;
        do {
            rng.nextBytes(buf);
            d = new BigInteger(1, buf);
        } while (d.signum() == 0 || d.compareTo(n) >= 0);
        return new LocalSigner(HexFormat.of().formatHex(d.toByteArray().length == 32
                ? d.toByteArray()
                : padTo32(d)));
    }

    private static byte[] padTo32(BigInteger v) {
        byte[] raw = v.toByteArray();
        if (raw.length == 32) return raw;
        if (raw.length == 33 && raw[0] == 0) {
            byte[] trimmed = new byte[32];
            System.arraycopy(raw, 1, trimmed, 0, 32);
            return trimmed;
        }
        byte[] out = new byte[32];
        System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        return out;
    }

    @Override
    public byte[] pubKey() {
        return compressedPubKey.clone();
    }

    @Override
    public String address() {
        return address;
    }

    @Override
    public byte[] sign(byte[] sighash, String derivationKey) {
        if (sighash == null || sighash.length != 32) {
            throw new IllegalArgumentException("LocalSigner.sign: sighash must be 32 bytes");
        }
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privKey, DOMAIN));
        BigInteger[] rs = signer.generateSignature(sighash);
        BigInteger r = rs[0];
        BigInteger s = rs[1];
        // Low-S normalisation (BIP-62 / BSV policy).
        if (s.compareTo(HALF_N) > 0) {
            s = CURVE.getN().subtract(s);
        }
        return derEncode(r, s);
    }

    /** Exposes the private key scalar for sighash-injection helpers. */
    BigInteger privateKey() {
        return privKey;
    }

    static byte[] derEncode(BigInteger r, BigInteger s) {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            return new DERSequence(v).getEncoded("DER");
        } catch (Exception e) {
            throw new RuntimeException("LocalSigner: DER encoding failed", e);
        }
    }
}
