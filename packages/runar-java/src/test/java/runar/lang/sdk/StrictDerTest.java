package runar.lang.sdk;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F-242 (CL-BUG-160): strict DER (BIP66) for ECDSA signatures.
 *
 * <p>{@code conformance/sdk-der/vectors.json} is the cross-tier vector set:
 * every ok=false entry re-encodes a valid signature's (r, s), so only the
 * encoding can make it fail. BouncyCastle's {@code ASN1Sequence.getInstance}
 * reads BER long-form lengths and ignores SEQUENCE elements after the second,
 * so the ANF interpreter's real-crypto checkSig verified those as valid.
 *
 * <p>Proves: {@link AnfInterpreter#verifyEcdsaReal} reaches the fixture
 * verdict on every vector. Does not prove the envelope path
 * ({@code EnvelopeInteropTest#rejectionVectors} replays the fixture's der-*
 * vectors) or anything about curve arithmetic.
 */
class StrictDerTest {

    @Test
    @SuppressWarnings("unchecked")
    void verifyEcdsaRealReachesFixtureVerdict() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-der", "vectors.json");
        Map<String, Object> fixture = (Map<String, Object>) Json.parse(Files.readString(p, StandardCharsets.UTF_8));
        String pub = (String) fixture.get("pubkey");
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) fixture.get("vectors");
        assertTrue(vectors.stream().anyMatch(v -> Boolean.TRUE.equals(v.get("ok"))), "no controls");
        assertTrue(vectors.stream().anyMatch(v -> Boolean.FALSE.equals(v.get("ok"))), "no refusals");
        for (Map<String, Object> v : vectors) {
            byte[] digest = HexFormat.of().parseHex((String) v.get("digest"));
            boolean got = AnfInterpreter.verifyEcdsaReal(v.get("sig"), pub, digest);
            assertEquals(v.get("ok"), got, (String) v.get("id"));
        }
    }
}
