package runar.lang.sdk;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

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
}
