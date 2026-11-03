package runar.lang.sdk;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * N-316: {@code matchesArtifact} must treat codeSepIndexSlots and
 * codePartLenSlots as variable script elements even when
 * {@code constructorSlots} is empty.
 *
 * <p>Replays the shared cross-tier fixture
 * {@code conformance/sdk-matches-artifact/fixtures.json} (also replayed by the
 * TS, Go, Rust, Python, Zig and Ruby SDKs). Its first artifact is real compiler
 * output for a stateful contract with no constructor args.
 *
 * <p>Proves: an honest deployment of such an artifact matches it, and a script
 * differing in one code byte before/after the slot does not.
 * Does NOT prove: on-chain spendability, or slot layouts beyond the fixture.
 */
class N316MatchesArtifactSlotOnlyTest {

    @SuppressWarnings("unchecked")
    @Test
    void slotOnlyArtifactsMatchTheirHonestDeployments() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-matches-artifact", "fixtures.json");
        Map<String, Object> fixture = (Map<String, Object>) Json.parse(Files.readString(p));
        List<Object> cases = (List<Object>) fixture.get("cases");
        assertFalse(cases.isEmpty());
        for (Object o : cases) {
            Map<String, Object> c = (Map<String, Object>) o;
            RunarArtifact artifact = RunarArtifact.fromJson(toJson(c.get("artifact")));
            boolean got = ScriptUtils.matchesArtifact(artifact, (String) c.get("script_hex"));
            assertEquals(c.get("expected"), got, "case " + c.get("name"));
        }
    }

    /** Minimal serializer for the parsed fixture tree (strings are plain hex/identifiers). */
    private static String toJson(Object v) {
        if (v == null) return "null";
        if (v instanceof Map<?, ?> m) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(toJson(e.getKey())).append(':').append(toJson(e.getValue()));
            }
            return sb.append('}').toString();
        }
        if (v instanceof List<?> l) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(toJson(l.get(i)));
            }
            return sb.append(']').toString();
        }
        if (v instanceof String s) {
            return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
        }
        return v.toString();
    }
}
