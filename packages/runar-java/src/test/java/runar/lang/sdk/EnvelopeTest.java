package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnvelopeTest {

    private static final BigInteger ALICE_PRIV = BigInteger.ONE;
    private static final BigInteger BOB_PRIV = BigInteger.valueOf(2);

    private static byte[] derEncodeLowS(BigInteger r, BigInteger s) {
        BigInteger halfN = LocalSigner.DOMAIN.getN().shiftRight(1);
        if (s.compareTo(halfN) > 0) {
            s = LocalSigner.DOMAIN.getN().subtract(s);
        }
        try {
            org.bouncycastle.asn1.ASN1EncodableVector v = new org.bouncycastle.asn1.ASN1EncodableVector();
            v.add(new org.bouncycastle.asn1.ASN1Integer(r));
            v.add(new org.bouncycastle.asn1.ASN1Integer(s));
            return new org.bouncycastle.asn1.DERSequence(v).getEncoded();
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static Envelope.SignFn signerFor(BigInteger priv) {
        return digest -> {
            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
            signer.init(true, new ECPrivateKeyParameters(priv, LocalSigner.DOMAIN));
            BigInteger[] rs = signer.generateSignature(digest);
            return derEncodeLowS(rs[0], rs[1]);
        };
    }

    private static String pubkeyHex(BigInteger priv) {
        ECPoint pub = LocalSigner.DOMAIN.getG().multiply(priv).normalize();
        byte[] compressed = pub.getEncoded(true);
        StringBuilder sb = new StringBuilder(compressed.length * 2);
        for (byte b : compressed) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    // -------------------------------------------------------------------
    // canonicalJson
    // -------------------------------------------------------------------

    @Test
    void canonicalJsonOrderIndependent() {
        Map<String, Object> a = new LinkedHashMap<>(); a.put("a", 1); a.put("b", 2);
        Map<String, Object> b = new LinkedHashMap<>(); b.put("b", 2); b.put("a", 1);
        assertEquals(Envelope.canonicalJson(a), Envelope.canonicalJson(b));
        assertEquals("{\"a\":1,\"b\":2}", Envelope.canonicalJson(a));
    }

    @Test
    void canonicalJsonNested() {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("z", 1); inner.put("a", Arrays.asList(3, 2, 1));
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("y", 1); nested.put("x", 2);
        Map<String, Object> top = new LinkedHashMap<>();
        top.put("outer", inner);
        top.put("list", Arrays.asList(nested));
        top.put("n", null);
        top.put("b", true);
        top.put("s", "hi");
        String got = Envelope.canonicalJson(top);
        assertEquals(
            "{\"b\":true,\"list\":[{\"x\":2,\"y\":1}],\"n\":null,\"outer\":{\"a\":[3,2,1],\"z\":1},\"s\":\"hi\"}",
            got);
    }

    // -------------------------------------------------------------------
    // sign + verify
    // -------------------------------------------------------------------

    private Envelope.SignedEnvelope sign(BigInteger priv, Map<String, Object> data, long nowMs) {
        Envelope.SignEnvelopeOpts o = new Envelope.SignEnvelopeOpts();
        o.data = data;
        o.signer = signerFor(priv);
        o.pubkey = pubkeyHex(priv);
        o.nowMs = nowMs;
        return Envelope.sign(o);
    }

    @Test
    void roundTrip() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("kind", "hello");
        data.put("n", 7);
        Envelope.SignedEnvelope env = sign(ALICE_PRIV, data, 1_000_000_000_000L);
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = env;
        vo.nowMs = 1_000_000_000_500L;
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertTrue(r.ok, "reason=" + r.reason);
        assertEquals("hello", r.data.get("kind"));
    }

    @Test
    void missingFields() {
        Map<String, Object> data = new LinkedHashMap<>(); data.put("ok", 1);
        Envelope.SignedEnvelope env = sign(ALICE_PRIV, data, 1_000_000_000_000L);
        Envelope.SignedEnvelope broken = new Envelope.SignedEnvelope(env.payload, "", env.pubkey, env.nonce, env.expiresAt);
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = broken; vo.nowMs = 1_000_000_000_500L;
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertFalse(r.ok);
        assertEquals(Envelope.VerifyEnvelopeReason.MISSING_FIELDS, r.reason);
    }

    @Test
    void expired() {
        Map<String, Object> data = new LinkedHashMap<>(); data.put("ok", 1);
        Envelope.SignedEnvelope env = sign(ALICE_PRIV, data, 1_000_000_000_000L);
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = env;
        vo.nowMs = 1_000_000_000_000L + 1_000_000L;
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertEquals(Envelope.VerifyEnvelopeReason.EXPIRED, r.reason);
    }

    @Test
    void badJson() {
        Map<String, Object> data = new LinkedHashMap<>(); data.put("ok", 1);
        Envelope.SignedEnvelope env = sign(ALICE_PRIV, data, 1_000_000_000_000L);
        Envelope.SignedEnvelope broken = new Envelope.SignedEnvelope("not json{", env.sig, env.pubkey, env.nonce, env.expiresAt);
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = broken; vo.nowMs = 1_000_000_000_500L;
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertEquals(Envelope.VerifyEnvelopeReason.BAD_JSON, r.reason);
    }

    @Test
    void envelopeMismatch() {
        Map<String, Object> data = new LinkedHashMap<>(); data.put("ok", 1);
        Envelope.SignedEnvelope env = sign(ALICE_PRIV, data, 1_000_000_000_000L);
        Envelope.SignedEnvelope tampered = new Envelope.SignedEnvelope(env.payload, env.sig, env.pubkey, env.nonce + 1, env.expiresAt);
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = tampered; vo.nowMs = 1_000_000_000_500L;
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertEquals(Envelope.VerifyEnvelopeReason.ENVELOPE_MISMATCH, r.reason);
        assertNotNull(r.data);
    }

    @Test
    void badSig() {
        Map<String, Object> data = new LinkedHashMap<>(); data.put("ok", 1);
        Envelope.SignedEnvelope env = sign(ALICE_PRIV, data, 1_000_000_000_000L);
        int mid = env.sig.length() / 2;
        char flip = env.sig.charAt(mid) == '1' ? '2' : '1';
        String flipped = env.sig.substring(0, mid) + flip + env.sig.substring(mid + 1);
        Envelope.SignedEnvelope broken = new Envelope.SignedEnvelope(env.payload, flipped, env.pubkey, env.nonce, env.expiresAt);
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = broken; vo.nowMs = 1_000_000_000_500L;
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertEquals(Envelope.VerifyEnvelopeReason.BAD_SIG, r.reason);
    }

    @Test
    void pubkeyNotAllowed() {
        Map<String, Object> data = new LinkedHashMap<>(); data.put("ok", 1);
        Envelope.SignedEnvelope env = sign(ALICE_PRIV, data, 1_000_000_000_000L);
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = env;
        vo.expectedKeys = Arrays.asList(pubkeyHex(BOB_PRIV));
        vo.nowMs = 1_000_000_000_500L;
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertEquals(Envelope.VerifyEnvelopeReason.PUBKEY_NOT_ALLOWED, r.reason);
    }

    @Test
    void pubkeyAllowed() {
        Map<String, Object> data = new LinkedHashMap<>(); data.put("ok", 1);
        Envelope.SignedEnvelope env = sign(ALICE_PRIV, data, 1_000_000_000_000L);
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = env;
        vo.expectedKeys = Arrays.asList(env.pubkey);
        vo.nowMs = 1_000_000_000_500L;
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertTrue(r.ok);
    }
}
