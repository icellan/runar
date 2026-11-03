package runar.lang.sdk;

import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-320: the state-reading paths must refuse a hostile script with the typed
 * error, never throw a raw runtime exception, hang or fabricate state.
 *
 * <p>Replays {@code conformance/sdk-matches-artifact/hostile-state.json} — the
 * N-317 hostile scripts of {@code hostile.json} with expected outcomes for
 * {@code StateSerializer.extractFromScript}, {@code RunarContract.fromUtxo}
 * and {@code fromTxId} (replayed by all 7 SDKs) — and calls the three push
 * readers directly on a signed byte: {@code Integer.parseInt} accepts a
 * leading '+' or '-', so "-1" read as opcode -1, took the direct-push branch
 * with a length of -2 and threw StringIndexOutOfBoundsException.
 *
 * <p>Proves: for each of the 30 scripts, extractFromScript on the stateful
 * artifact returns exactly the expected state / null / plain
 * {@link IllegalArgumentException}, and fromUtxo and fromTxId either reconnect
 * or throw a plain IllegalArgumentException (a NumberFormatException,
 * StringIndexOutOfBoundsException or any other exception fails it) — an
 * odd-length, non-hex or non-ASCII script is refused before any reader runs,
 * and a stateful artifact over a script with no state section is refused (C10,
 * as in TS) instead of carrying constructor-initial state; decodePushData,
 * decodePushDataState and findLastOpReturn refuse a '+'/'-' byte with a plain
 * IllegalArgumentException; the replay stays inside a thread-CPU budget.
 * Does NOT prove: on-chain spendability of a reconnected contract; artifact
 * shapes beyond the fixture's two; WHICH IllegalArgumentException the refusal
 * is (this tier's typed malformed error is that class).
 */
class N320HostileStatePathsTest {

    private static final long CPU_BUDGET_NANOS = 20_000_000_000L;

    private static String outcome(Supplier<String> run) {
        try {
            return run.get();
        } catch (RuntimeException e) {
            return e.getClass() == IllegalArgumentException.class ? "malformed" : "error:" + e;
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    void hostileScriptsAreRefusedOnTheStateReadingPaths() throws Exception {
        Path dir = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-matches-artifact");
        Map<String, Object> fx = (Map<String, Object>) Json.parse(Files.readString(dir.resolve("hostile.json")));
        Map<String, Object> sfx = (Map<String, Object>) Json.parse(Files.readString(dir.resolve("hostile-state.json")));
        List<Object> cases = (List<Object>) fx.get("cases");
        List<Object> want = (List<Object>) sfx.get("cases");
        assertTrue(!cases.isEmpty() && cases.size() == want.size(), "fixture mismatch");
        Map<String, RunarArtifact> artifacts = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : ((Map<String, Object>) fx.get("artifacts")).entrySet()) {
            artifacts.put(e.getKey(), RunarArtifact.fromJson(toJson(e.getValue())));
        }

        assertTimeoutPreemptively(Duration.ofSeconds(120), () -> {
            var bean = ManagementFactory.getThreadMXBean();
            long start = bean.getCurrentThreadCpuTime();
            MockProvider provider = new MockProvider();
            List<String> diffs = new ArrayList<>();
            for (int i = 0; i < cases.size(); i++) {
                Map<String, Object> c = (Map<String, Object>) cases.get(i);
                Map<String, Object> w = (Map<String, Object>) want.get(i);
                String name = (String) c.get("name");
                assertEquals(name, w.get("name"), "case order");
                String script = scriptOf(c);
                String txid = String.format("%02x", i).repeat(32);
                UTXO utxo = new UTXO(txid, 0, 1000L, script);
                provider.addUtxo("hostile-address", utxo);

                String wantState = w.get("state") == null ? "null"
                    : w.get("state") instanceof Map<?, ?> m ? stringValues(m).toString() : (String) w.get("state");
                String gotState = outcome(() -> {
                    Map<String, Object> s = StateSerializer.extractFromScript(artifacts.get("stateful"), script);
                    return s == null ? "null" : stringValues(s).toString();
                });
                if (!wantState.equals(gotState)) {
                    diffs.add("extractFromScript " + name + ": want " + wantState + ", got " + gotState);
                }

                RunarArtifact a = artifacts.get((String) c.get("artifact"));
                String gotUtxo = outcome(() -> { RunarContract.fromUtxo(a, utxo); return "ok"; });
                if (!w.get("fromUtxo").equals(gotUtxo)) {
                    diffs.add("fromUtxo " + name + ": want " + w.get("fromUtxo") + ", got " + gotUtxo);
                }
                String gotTx = outcome(() -> { RunarContract.fromTxId(a, txid, 0, provider); return "ok"; });
                if (!w.get("fromUtxo").equals(gotTx)) {
                    diffs.add("fromTxId " + name + ": want " + w.get("fromUtxo") + ", got " + gotTx);
                }
            }
            assertEquals(List.of(), diffs);
            long used = bean.getCurrentThreadCpuTime() - start;
            assertTrue(used < CPU_BUDGET_NANOS, "replay used " + used / 1_000_000 + " ms CPU");
        });
    }

    @Test
    void pushReadersRefuseASignedByte() {
        List<String> diffs = new ArrayList<>();
        Map<String, Supplier<String>> probes = new LinkedHashMap<>();
        probes.put("decodePushData(-1aa)", () -> ScriptUtils.decodePushData("-1aa", 0).dataHex());
        probes.put("decodePushData(+1aa)", () -> ScriptUtils.decodePushData("+1aa", 0).dataHex());
        probes.put("decodePushData(4c-f)", () -> ScriptUtils.decodePushData("4c-faa", 0).dataHex());
        probes.put("decodePushDataState(-1aa)", () -> ScriptUtils.decodePushDataState("-1aa", 0).dataHex());
        probes.put("decodePushDataState(4d+1+0)", () -> ScriptUtils.decodePushDataState("4d+1+0aa", 0).dataHex());
        probes.put("findLastOpReturn(4c-f)", () -> String.valueOf(ScriptUtils.findLastOpReturn("4c-f")));
        probes.put("findLastOpReturn(-16a)", () -> String.valueOf(ScriptUtils.findLastOpReturn("-16a")));
        for (Map.Entry<String, Supplier<String>> p : probes.entrySet()) {
            String got = outcome(p.getValue());
            if (!got.equals("malformed")) diffs.add(p.getKey() + ": want malformed, got " + got);
        }
        assertEquals(List.of(), diffs);
    }

    private static Map<String, String> stringValues(Map<?, ?> m) {
        Map<String, String> out = new java.util.TreeMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) out.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
        return out;
    }

    private static String scriptOf(Map<String, Object> c) {
        String repeat = c.get("repeat") == null ? "" : (String) c.get("repeat");
        int count = c.get("count") == null ? 0 : ((Number) c.get("count")).intValue();
        String suffix = c.get("suffix") == null ? "" : (String) c.get("suffix");
        return c.get("prefix") + repeat.repeat(count) + suffix;
    }

    /** Minimal serializer for the parsed fixture tree (same as N317HostileUtxoScriptsTest). */
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
