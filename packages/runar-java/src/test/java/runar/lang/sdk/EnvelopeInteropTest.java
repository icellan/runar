package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-tier interop test for the signed-envelope wire protocol. Loads
 * {@code conformance/sdk-envelope/fixtures.json} (TS reference) and asserts:
 * <ul>
 *   <li>{@link Envelope#canonicalJson} byte-parity on every input vector.</li>
 *   <li>{@link Envelope#verify} accepts the valid envelope at {@code verify_now_ms}.</li>
 *   <li>{@link Envelope#verify} returns the listed reason for every rejection vector.</li>
 * </ul>
 *
 * See CLAUDE.md §"Seven SDKs Must Stay in Sync".
 */
class EnvelopeInteropTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadFixture() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-envelope", "fixtures.json");
        String text = Files.readString(p);
        return (Map<String, Object>) Json.parse(text);
    }

    @Test
    @SuppressWarnings("unchecked")
    void canonicalJsonVectors() throws Exception {
        Map<String, Object> fixture = loadFixture();
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) fixture.get("canonical_json_vectors");
        for (int i = 0; i < vectors.size(); i++) {
            Map<String, Object> v = vectors.get(i);
            String got = Envelope.canonicalJson(v.get("input"));
            String expected = (String) v.get("expected");
            assertEquals(expected, got, "vector " + i);
        }
    }

    @SuppressWarnings("unchecked")
    private static Envelope.SignedEnvelope envelopeFromMap(Map<String, Object> m) {
        return new Envelope.SignedEnvelope(
            (String) m.get("payload"),
            (String) m.get("sig"),
            (String) m.get("pubkey"),
            ((Number) m.get("nonce")).longValue(),
            ((Number) m.get("expiresAt")).longValue()
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void verifyValidEnvelope() throws Exception {
        Map<String, Object> fixture = loadFixture();
        Envelope.SignedEnvelope env = envelopeFromMap((Map<String, Object>) fixture.get("valid_envelope"));
        Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
        vo.envelope = env;
        vo.nowMs = ((Number) fixture.get("verify_now_ms")).longValue();
        Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
        assertTrue(r.ok, "reason=" + r.reason);
    }

    @Test
    @SuppressWarnings("unchecked")
    void rejectionVectors() throws Exception {
        Map<String, Object> fixture = loadFixture();
        long verifyNowMs = ((Number) fixture.get("verify_now_ms")).longValue();
        List<Map<String, Object>> rejections = (List<Map<String, Object>>) fixture.get("rejection_vectors");
        for (Map<String, Object> rv : rejections) {
            String reasonWire = (String) rv.get("reason");
            Envelope.SignedEnvelope env = envelopeFromMap((Map<String, Object>) rv.get("envelope"));
            Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
            vo.envelope = env;
            vo.nowMs = verifyNowMs;
            Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
            assertFalse(r.ok, "rejection " + reasonWire + " should be ok=false");
            assertEquals(reasonWire, r.reason.wire, "rejection " + reasonWire);
        }
    }

    // -------------------------------------------------------------------
    // GAP-064 signing vectors
    // -------------------------------------------------------------------

    private static byte[] sha256(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    /** RFC 6979 deterministic ECDSA (plain-SHA-256 nonce) -> low-S DER. */
    private static byte[] signDeterministic(BigInteger priv, byte[] digest) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(priv, LocalSigner.DOMAIN));
        BigInteger[] rs = signer.generateSignature(digest);
        BigInteger r = rs[0];
        BigInteger s = rs[1];
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

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    /**
     * GAP-064 cross-tier signing reproduction. Signing the SAME payload with
     * the SAME key (priv=1) via RFC 6979 deterministic ECDSA (plain-SHA-256
     * nonce, low-S) MUST yield the byte-identical DER signature the TS
     * reference committed.
     */
    @Test
    @SuppressWarnings("unchecked")
    void signingVectors() throws Exception {
        Map<String, Object> fixture = loadFixture();
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) fixture.get("signing_vectors");
        if (vectors == null || vectors.isEmpty()) {
            throw new AssertionError("signing_vectors missing or empty");
        }
        BigInteger alicePriv = BigInteger.ONE;
        for (Map<String, Object> v : vectors) {
            String id = (String) v.get("_vector_id");
            String expectedPayload = (String) v.get("expected_payload");
            String expectedSig = (String) v.get("expected_sig");

            // Drift guard: re-derive the canonical payload from data + lifetime.
            Map<String, Object> merged = new LinkedHashMap<>((Map<String, Object>) v.get("data"));
            merged.put("nonce", v.get("nonce"));
            merged.put("expiresAt", v.get("expiresAt"));
            String payload = Envelope.canonicalJson(merged);
            assertEquals(expectedPayload, payload, "vector " + id + ": payload");

            byte[] digest = sha256(payload.getBytes(StandardCharsets.UTF_8));
            String der = toHex(signDeterministic(alicePriv, digest));
            assertEquals(expectedSig, der, "vector " + id + ": signature divergence");
        }
    }

    /**
     * RFC 8785 §3.2.2.2 — canonical_json MUST reject malformed Unicode
     * (lone surrogate). See audits/canonical-json-rfc8785-parity.md §3 rec 6
     * (D6). Today no tier rejects; this test pins the desired behaviour and
     * gates the future fix.
     *
     * Inputs are reconstructed from a UTF-16 code-unit array so the JSON
     * parser's per-tier lone-surrogate handling does not mask the
     * canonical_json behaviour we are gating.
     */
    @Test
    @SuppressWarnings("unchecked")
    void canonicalJsonRejectionVectors() throws Exception {
        Map<String, Object> fixture = loadFixture();
        List<Map<String, Object>> rvs =
            (List<Map<String, Object>>) fixture.get("canonical_json_rejection_vectors");
        if (rvs == null || rvs.isEmpty()) {
            throw new AssertionError("canonical_json_rejection_vectors missing or empty");
        }
        for (Map<String, Object> v : rvs) {
            String id = (String) v.get("_vector_id");
            String key = (String) v.get("input_object_key");
            List<Object> units = (List<Object>) v.get("input_value_utf16_units");
            // Java `char` is a UTF-16 code unit; construct the bad String
            // from the raw code units, lone surrogates and all.
            char[] chars = new char[units.size()];
            for (int i = 0; i < units.size(); i++) {
                chars[i] = (char) ((Number) units.get(i)).intValue();
            }
            String bad = new String(chars);
            Map<String, Object> input = new java.util.LinkedHashMap<>();
            input.put(key, bad);
            Throwable caught = null;
            String got = null;
            try {
                got = Envelope.canonicalJson(input);
            } catch (Throwable t) {
                caught = t;
            }
            if (caught == null) {
                throw new AssertionError(
                    "vector " + id + ": canonical_json MUST reject lone surrogate; got " + got);
            }
        }
    }
    // -------------------------------------------------------------------
    // R-260 — shared payload depth bound
    // -------------------------------------------------------------------

    /**
     * verify must bound payload nesting ITSELF rather than inherit whatever cap
     * its JSON parser happens to impose, because that cap differs per tier
     * (ruby 100, rust 127, ts/go/python/zig none) and THIS tier had no cap at
     * all: {@link Json}'s readValue/readObject/readArray are mutually recursive
     * and {@code verify} catches {@code Exception}, not {@code Error}, so a
     * ~10 KB deep payload threw {@link StackOverflowError} straight out of
     * {@code verify} — a contract escape on unauthenticated input, at a depth
     * set by the JVM's {@code -Xss} flag rather than by the protocol.
     */
    @Test
    @SuppressWarnings("unchecked")
    void payloadDepthVectors() throws Exception {
        Map<String, Object> fixture = loadFixture();
        long verifyNowMs = ((Number) fixture.get("verify_now_ms")).longValue();
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) fixture.get("depth_vectors");
        assertFalse(vectors.isEmpty(), "depth_vectors missing or empty");
        for (Map<String, Object> dv : vectors) {
            String vid = (String) dv.get("_vector_id");
            Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
            vo.envelope = envelopeFromMap((Map<String, Object>) dv.get("envelope"));
            vo.nowMs = verifyNowMs;
            Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
            if (Boolean.TRUE.equals(dv.get("expect_ok"))) {
                assertTrue(r.ok, vid + ": expected ok=true, got reason=" + r.reason);
            } else {
                assertFalse(r.ok, vid + ": expected ok=false");
                assertEquals(dv.get("reason"), r.reason.wire, vid);
            }
        }
    }

    /**
     * The bound is part of the wire contract, so the fixture pins it and every
     * tier asserts its own constant against the fixture's number.
     */
    @Test
    void payloadDepthLimitMatchesFixture() throws Exception {
        Map<String, Object> fixture = loadFixture();
        assertEquals(
            ((Number) fixture.get("payload_depth_limit")).intValue(),
            Envelope.MAX_ENVELOPE_PAYLOAD_DEPTH);
    }

    // -------------------------------------------------------------------
    // R-261 — explicit clock options
    // -------------------------------------------------------------------

    /**
     * An EXPLICIT clock override of 0 must mean the epoch, not "not supplied".
     * This tier read {@code nowMs != 0 ? nowMs : System.currentTimeMillis()},
     * so an explicit 0 fell back to the wall clock and returned {@code expired}
     * on an envelope that python, ruby, rust and zig all accepted. (Its
     * clockSkewMs was already correct — a field default of 5_000 that an
     * explicit 0 overrides — and cs1 is the control proving that.) A null in
     * the vector means the caller supplies nothing and the default applies, so
     * cs2 and cs3 redden if a fix drops the default instead of honouring zero.
     */
    @Test
    @SuppressWarnings("unchecked")
    void clockSkewVectors() throws Exception {
        Map<String, Object> fixture = loadFixture();
        Envelope.SignedEnvelope env = envelopeFromMap((Map<String, Object>) fixture.get("valid_envelope"));
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) fixture.get("clock_skew_vectors");
        assertFalse(vectors.isEmpty(), "clock_skew_vectors missing or empty");
        for (Map<String, Object> cv : vectors) {
            String vid = (String) cv.get("_vector_id");
            Envelope.VerifyEnvelopeOpts vo = new Envelope.VerifyEnvelopeOpts();
            vo.envelope = env;
            Number skew = (Number) cv.get("clock_skew_ms");
            if (skew != null) {
                vo.clockSkewMs = skew.longValue();
            }
            Number now = (Number) cv.get("now_ms");
            if (now != null) {
                vo.nowMs = now.longValue();
            }
            Envelope.VerifyEnvelopeResult r = Envelope.verify(vo);
            if (Boolean.TRUE.equals(cv.get("expect_ok"))) {
                assertTrue(r.ok, vid + ": expected ok=true, got reason=" + r.reason);
            } else {
                assertFalse(r.ok, vid + ": expected ok=false");
                assertEquals(cv.get("reason"), r.reason.wire, vid);
            }
        }
    }

}
