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
}
