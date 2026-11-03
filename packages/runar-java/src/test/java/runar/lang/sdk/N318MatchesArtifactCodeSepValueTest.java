package runar.lang.sdk;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * N-318: {@code matchesArtifact} must check the VALUE at every codeSepIndex
 * slot. Deploy bakes pushScriptNumber(codeSepIndex + shift) there (shift =
 * growth of every constructor slot, and every earlier codeSep slot, before
 * codeSepIndex); the matcher used to accept any element at the slot.
 *
 * <p>Replays the shared cross-tier vector
 * {@code conformance/sdk-matches-artifact/codesep.json} (also replayed by the
 * TS, Go, Rust, Python, Zig and Ruby SDKs): honest TS-SDK deployments of a
 * real compiled artifact and of a synthetic artifact whose baked values depend
 * on a variable-length constructor arg, plus forgeries differing only in the
 * number pushed at a codeSep slot.
 *
 * <p>Proves: honest deployments match whatever the constructor-arg width, and
 * a forged separator index (OP_0, off by one, non-minimal, unshifted) does not.
 * Does NOT prove: on-chain spendability of the honest scripts.
 */
class N318MatchesArtifactCodeSepValueTest {

    @SuppressWarnings("unchecked")
    @Test
    void codeSepSlotMustCarryTheDeployBakedValue() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-matches-artifact", "codesep.json");
        Map<String, Object> fixture = (Map<String, Object>) Json.parse(Files.readString(p));
        Map<String, Object> artifacts = (Map<String, Object>) fixture.get("artifacts");
        List<Object> cases = (List<Object>) fixture.get("cases");
        assertFalse(cases.isEmpty());
        List<String> wrong = new ArrayList<>();
        for (Object o : cases) {
            Map<String, Object> c = (Map<String, Object>) o;
            RunarArtifact artifact = RunarArtifact.fromJson(toJson(artifacts.get((String) c.get("artifact"))));
            boolean got = ScriptUtils.matchesArtifact(artifact, (String) c.get("script_hex"));
            if (!c.get("expected").equals(got)) wrong.add(c.get("name") + " (got " + got + ")");
        }
        assertEquals(List.of(), wrong, wrong.size() + " case(s) wrong");
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
