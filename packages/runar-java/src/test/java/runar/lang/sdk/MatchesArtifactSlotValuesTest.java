package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code matchesArtifact} must check what sits at each constructor slot, not
 * only the template bytes between slots: a push or small-integer opcode, the
 * same bytes at every reference of one param, and exactly
 * {@code fixedValueByteLength} bytes where the slot declares it. A stateful
 * artifact's script must carry an OP_RETURN after its code part.
 *
 * <p>Replays the shared cross-tier vector
 * {@code conformance/sdk-matches-artifact/slot-values.json} (also replayed by
 * the TS, Go, Rust, Python, Zig and Ruby SDKs), plus the TS unit cases for hex
 * case, {@code extractConstructorArgs} refusing a non-push opcode, and
 * {@code extractConstructorArgs} after a codeSepIndex slot wider than one byte.
 *
 * <p>Proves: honest deployments match; the forgeries in the vector do not;
 * {@link ContractScript#extractConstructorArgs} throws
 * {@link IllegalArgumentException} (this tier's malformed-script error) on a
 * non-push opcode at any reference of a param and reads an arg after a wide
 * codeSep slot from its deployed position.
 * Does NOT prove: that a slot push is minimally encoded, nor anything about
 * the length of the state after the OP_RETURN.
 */
class MatchesArtifactSlotValuesTest {

    private static final String G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> fixture() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-matches-artifact", "slot-values.json");
        return (Map<String, Object>) Json.parse(Files.readString(p));
    }

    @SuppressWarnings("unchecked")
    private static RunarArtifact artifact(Map<String, Object> fixture, String key) {
        Map<String, Object> artifacts = (Map<String, Object>) fixture.get("artifacts");
        return RunarArtifact.fromJson(toJson(artifacts.get(key)));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> cases(Map<String, Object> fixture) {
        return (List<Map<String, Object>>) (List<?>) fixture.get("cases");
    }

    @Test
    void replaysSlotValuesVector() throws Exception {
        Map<String, Object> fx = fixture();
        List<Map<String, Object>> cases = cases(fx);
        assertFalse(cases.isEmpty());
        List<String> wrong = new ArrayList<>();
        for (Map<String, Object> c : cases) {
            boolean got = ScriptUtils.matchesArtifact(artifact(fx, (String) c.get("artifact")), (String) c.get("script_hex"));
            if (!c.get("expected").equals(got)) wrong.add(c.get("name") + " (got " + got + ")");
        }
        assertEquals(List.of(), wrong, wrong.size() + " of " + cases.size() + " case(s) wrong");
    }

    @Test
    void slotValuesCompareWithoutRegardToHexCase() throws Exception {
        RunarArtifact owner2 = artifact(fixture(), "owner2");
        assertTrue(ScriptUtils.matchesArtifact(owner2, "21" + G + "ad21" + G.toUpperCase(Locale.ROOT) + "ac"));
    }

    @Test
    void extractConstructorArgsRefusesNonPushAtSlot() throws Exception {
        Map<String, Object> fx = fixture();
        Object[][] cases = {
            {"first reference", "owner2", "acad21" + G + "ac"},
            {"later reference", "owner2", "21" + G + "adacac"},
            {"SlotMatrix", "slotMatrix", "ac7b880111" + "7c9dac" + "21" + G + "879169" + "21" + G + "ac"},
        };
        List<String> accepted = new ArrayList<>();
        for (Object[] c : cases) {
            try {
                ContractScript.extractConstructorArgs(artifact(fx, (String) c[1]), (String) c[2]);
                accepted.add((String) c[0]);
            } catch (IllegalArgumentException expected) {
                // refused, as required
            }
        }
        assertEquals(List.of(), accepted, "accepted a non-push opcode at a constructor slot");
    }

    @Test
    void extractConstructorArgsStillReadsHonestDeployments() throws Exception {
        Map<String, Object> fx = fixture();
        RunarArtifact slotMatrix = artifact(fx, "slotMatrix");
        for (Map<String, Object> c : cases(fx)) {
            if (Boolean.TRUE.equals(c.get("expected")) && "slotMatrix".equals(c.get("artifact"))) {
                List<Object> args = ContractScript.extractConstructorArgs(slotMatrix, (String) c.get("script_hex"));
                assertEquals(BigInteger.valueOf(17), args.get(0), (String) c.get("name"));
                assertEquals(G, args.get(2), (String) c.get("name"));
            }
            if ("owner2-honest".equals(c.get("name"))) {
                assertEquals(List.of(G), ContractScript.extractConstructorArgs(artifact(fx, "owner2"), (String) c.get("script_hex")));
            }
        }
    }

    @Test
    void extractConstructorArgsAfterWideCodeSepSlot() {
        // Hand-built: a codeSepIndex slot at byte 1 with codeSepIndex 140, baked
        // as 143 (`02 8f00`), then a constructor slot at byte 3. Script pinned
        // by the TS SDK's RunarContract.getLockingScript().
        RunarArtifact art = RunarArtifact.fromJson(
            "{\"version\":\"runar-v1.0.0-rc.1\",\"compilerVersion\":\"1.0.0-rc.1\",\"contractName\":\"CodeSepBeforeSlot\","
                + "\"abi\":{\"constructor\":{\"params\":[{\"name\":\"x\",\"type\":\"ByteString\"}]},\"methods\":[]},"
                + "\"script\":\"5100520053\",\"constructorSlots\":[{\"paramIndex\":0,\"byteOffset\":3}],"
                + "\"codeSepIndexSlots\":[{\"byteOffset\":1,\"codeSepIndex\":140}]}");
        String script = "51028f005203aabbcc53";
        assertTrue(ScriptUtils.matchesArtifact(art, script));
        assertEquals(List.of("aabbcc"), ContractScript.extractConstructorArgs(art, script));
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
