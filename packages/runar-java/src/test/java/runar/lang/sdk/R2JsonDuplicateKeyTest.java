package runar.lang.sdk;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R2-DUPKEY: {@link Json#parseRejectingDuplicateKeys} is the envelope's
 * payload parser. A repeated key in one object (compared after unescaping)
 * throws; the same key in different objects does not. Plain
 * {@link Json#parse} keeps its keep-last behaviour for artifact loading.
 *
 * <p>Proves the parser-level rule; the shared fixture's duplicate_key_vectors
 * (EnvelopeInteropTest) prove verify returns bad-json at the right step.
 */
class R2JsonDuplicateKeyTest {

    @Test
    void envelopeParserRejectsDuplicateKeysPerObject() {
        for (String json : List.of(
                "{\"a\":1,\"a\":2}",
                "{\"m\":{\"a\":1,\"a\":1}}",
                "{\"l\":[{\"b\":1,\"b\":2}]}",
                "{\"\\u0061\":1,\"a\":2}",
                "{\"\uD83D\uDE00\":1,\"\\ud83d\\ude00\":2}")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Json.parseRejectingDuplicateKeys(json), "must reject: " + json);
            assertTrue(e.getMessage().contains("duplicate key"), json + ": " + e.getMessage());
        }
        // Same key in different objects is not a duplicate.
        Json.parseRejectingDuplicateKeys("{\"a\":{\"a\":1},\"l\":[{\"a\":1},{\"a\":2}],\"\\u0041\":1}");
        // Artifact loading keeps its keep-last behaviour.
        assertEquals(2L, ((Map<?, ?>) Json.parse("{\"a\":1,\"a\":2}")).get("a"));
    }
}
