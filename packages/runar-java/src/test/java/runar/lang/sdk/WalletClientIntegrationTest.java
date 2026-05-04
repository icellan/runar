package runar.lang.sdk;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Live BRC-100 WalletClient round-trip integration test.
 *
 * <p>Mirrors {@code integration/ruby/spec/wallet_client_spec.rb}. Environment-gated
 * via {@link EnabledIfEnvironmentVariable}: runs only when
 * {@code RUNAR_WALLET_ENDPOINT} is set to the base URL of a BRC-100
 * JSON-over-HTTP wallet endpoint. When unset, the test is skipped cleanly so
 * local + CI runs stay green without any wallet setup.
 *
 * <p>Optional env:
 * <ul>
 *   <li>{@code RUNAR_WALLET_ENDPOINT} — base URL, required</li>
 *   <li>{@code RUNAR_WALLET_AUTH} — bearer token, optional</li>
 *   <li>{@code RUNAR_WALLET_BASKET} — basket name, default {@code "runar-integration-test"}</li>
 * </ul>
 *
 * <p>Asserts the same shape Ruby asserts:
 * <ul>
 *   <li>{@code getPublicKey} returns a 33-byte compressed pubkey
 *       (66 hex chars, prefix 02/03).</li>
 *   <li>{@code listOutputs} returns an array; entries (if any) expose at least
 *       one of {@code outpoint} / {@code satoshis} / {@code lockingScript}.</li>
 * </ul>
 */
@EnabledIfEnvironmentVariable(named = "RUNAR_WALLET_ENDPOINT", matches = ".+")
class WalletClientIntegrationTest {

    private static final Pattern HEX = Pattern.compile("^[0-9a-fA-F]+$");

    private final HttpClient client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return (v == null || v.isEmpty()) ? fallback : v;
    }

    private Object post(String endpoint, String method, String jsonBody) throws Exception {
        String trimmed = endpoint.endsWith("/")
            ? endpoint.substring(0, endpoint.length() - 1)
            : endpoint;
        HttpRequest.Builder b = HttpRequest.newBuilder()
            .uri(URI.create(trimmed + "/" + method))
            .timeout(Duration.ofSeconds(30))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
        String authToken = System.getenv("RUNAR_WALLET_AUTH");
        if (authToken != null && !authToken.isEmpty()) {
            b.header("Authorization", "Bearer " + authToken);
        }
        HttpResponse<String> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            fail("wallet " + method + " HTTP " + resp.statusCode() + ": " + resp.body());
        }
        return Json.parse(resp.body());
    }

    @Test
    void walletClientLiveRoundTrip() throws Exception {
        String endpoint = System.getenv("RUNAR_WALLET_ENDPOINT");
        assertNotNull(endpoint, "RUNAR_WALLET_ENDPOINT not set");
        String basket = env("RUNAR_WALLET_BASKET", "runar-integration-test");

        // 1. getPublicKey: must return a 33-byte compressed secp256k1 key.
        String pubKeyBody = "{\"protocolID\":[2,\"runar integration\"],\"keyID\":\"1\"}";
        Object pubResp = post(endpoint, "getPublicKey", pubKeyBody);
        assertTrue(pubResp instanceof Map, "getPublicKey: expected JSON object, got " + pubResp);
        @SuppressWarnings("unchecked")
        Map<String, Object> pubMap = (Map<String, Object>) pubResp;
        Object pubKeyObj = pubMap.getOrDefault("publicKey", pubMap.get("publicKeyHex"));
        assertNotNull(pubKeyObj, "getPublicKey: missing publicKey in response: " + pubMap);
        assertTrue(pubKeyObj instanceof String, "getPublicKey: publicKey not a string: " + pubKeyObj);
        String pubKey = (String) pubKeyObj;
        assertEquals(66, pubKey.length(),
            "getPublicKey: expected 66 hex chars, got " + pubKey.length() + " (" + pubKey + ")");
        String prefix = pubKey.substring(0, 2);
        assertTrue("02".equals(prefix) || "03".equals(prefix),
            "getPublicKey: expected compressed prefix 02/03, got " + prefix);
        assertTrue(HEX.matcher(pubKey).matches(),
            "getPublicKey: not hex: " + pubKey);

        // 2. listOutputs: must return an array (possibly empty).
        String listBody = "{\"basket\":\"" + basket + "\",\"tags\":[],\"limit\":10}";
        Object listResp = post(endpoint, "listOutputs", listBody);
        assertTrue(listResp instanceof Map, "listOutputs: expected JSON object, got " + listResp);
        @SuppressWarnings("unchecked")
        Map<String, Object> listMap = (Map<String, Object>) listResp;
        Object outputsObj = listMap.getOrDefault("outputs", List.of());
        assertTrue(outputsObj instanceof List, "listOutputs: outputs not an array: " + outputsObj);
        @SuppressWarnings("unchecked")
        List<Object> outputs = (List<Object>) outputsObj;
        for (int i = 0; i < outputs.size(); i++) {
            Object out = outputs.get(i);
            assertTrue(out instanceof Map,
                "listOutputs[" + i + "]: not an object: " + out);
            @SuppressWarnings("unchecked")
            Map<String, Object> outMap = (Map<String, Object>) out;
            boolean hasField = outMap.containsKey("outpoint")
                || outMap.containsKey("satoshis")
                || outMap.containsKey("lockingScript");
            assertTrue(hasField,
                "listOutputs[" + i + "]: missing canonical outpoint/satoshis/lockingScript: " + outMap);
        }
    }
}
