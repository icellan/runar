package runar.lang.sdk.ordinals;

import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.Json;
import runar.lang.sdk.MockProvider;
import runar.lang.sdk.MockSigner;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.ScriptUtils;
import runar.lang.sdk.UTXO;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-317: one hostile UTXO script must not take {@code TokenWallet.getUtxos}
 * down, and {@code ScriptUtils.matchesArtifact} must agree with the TS SDK on
 * every malformed shape.
 *
 * <p>Replays the shared cross-tier vector
 * {@code conformance/sdk-matches-artifact/hostile.json} (also replayed by the
 * TS, Go, Rust, Python, Zig and Ruby SDKs): odd-length and non-hex scripts,
 * truncated OP_PUSHDATA1/2/4, OP_PUSHDATA4 lengths with the high bit set, a
 * push running past the slot, empty and short scripts and ~1 MiB scripts,
 * beside SDK-built genuine instances.
 *
 * <p>Proves: matchesArtifact gives exactly the fixture's outcome per vector
 * (true / false / a plain {@link IllegalArgumentException}; a
 * NumberFormatException or StringIndexOutOfBoundsException fails it);
 * getUtxos keeps exactly the genuine instances for a stateful and a stateless
 * artifact and never throws; the replay stays inside a thread-CPU budget
 * (and is cut off preemptively at a wall-clock cap).
 * Does NOT prove: on-chain spendability of the kept UTXOs, artifact shapes
 * beyond the fixture's two, or anything about a forged codeSepIndex element
 * (N-318).
 */
class N317HostileUtxoScriptsTest {

    // Measured: well under a second of CPU after the fix.
    private static final long CPU_BUDGET_NANOS = 20_000_000_000L;

    @SuppressWarnings("unchecked")
    @Test
    void hostileScriptsAreRejectedWithoutAbortingTheListing() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-matches-artifact", "hostile.json");
        Map<String, Object> fx = (Map<String, Object>) Json.parse(Files.readString(p));
        Map<String, Object> artifactsJson = (Map<String, Object>) fx.get("artifacts");
        List<Object> cases = (List<Object>) fx.get("cases");
        Map<String, RunarArtifact> artifacts = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : artifactsJson.entrySet()) {
            artifacts.put(e.getKey(), RunarArtifact.fromJson(toJson(e.getValue())));
        }

        assertTimeoutPreemptively(Duration.ofSeconds(120), () -> {
            var bean = ManagementFactory.getThreadMXBean();
            long start = bean.getCurrentThreadCpuTime();
            List<String> diffs = new ArrayList<>();
            for (Object o : cases) {
                Map<String, Object> c = (Map<String, Object>) o;
                String got;
                try {
                    got = ScriptUtils.matchesArtifact(artifacts.get((String) c.get("artifact")), scriptOf(c))
                        ? "match" : "no_match";
                } catch (RuntimeException e) {
                    got = e.getClass() == IllegalArgumentException.class ? "malformed" : "error:" + e;
                }
                if (!c.get("matches").equals(got)) {
                    diffs.add(c.get("name") + ": want " + c.get("matches") + ", got " + got);
                }
            }
            for (String name : artifacts.keySet()) {
                MockProvider provider = new MockProvider();
                MockSigner signer = new MockSigner();
                List<String> want = new ArrayList<>();
                for (int i = 0; i < cases.size(); i++) {
                    Map<String, Object> c = (Map<String, Object>) cases.get(i);
                    if (!name.equals(c.get("artifact")) || c.get("wallet") == null) continue;
                    String txid = String.format("%02x", i).repeat(32);
                    provider.addUtxo(signer.address(), new UTXO(txid, 0, 1000L, scriptOf(c)));
                    if (Boolean.TRUE.equals(c.get("wallet"))) want.add(txid);
                }
                List<String> kept = new ArrayList<>();
                try {
                    for (UTXO u : new TokenWallet(artifacts.get(name), provider, signer).getUtxos()) kept.add(u.txid());
                } catch (RuntimeException e) {
                    diffs.add("getUtxos (" + name + ") threw " + e);
                    continue;
                }
                if (!want.equals(kept)) diffs.add("getUtxos (" + name + "): want " + want + ", got " + kept);
            }
            assertEquals(List.of(), diffs);
            long used = bean.getCurrentThreadCpuTime() - start;
            assertTrue(used < CPU_BUDGET_NANOS, "replay used " + used / 1_000_000 + " ms CPU");
        });
    }

    private static String scriptOf(Map<String, Object> c) {
        String repeat = c.get("repeat") == null ? "" : (String) c.get("repeat");
        int count = c.get("count") == null ? 0 : ((Number) c.get("count")).intValue();
        String suffix = c.get("suffix") == null ? "" : (String) c.get("suffix");
        return c.get("prefix") + repeat.repeat(count) + suffix;
    }

    /** Minimal serializer for the parsed fixture tree (same as N316MatchesArtifactSlotOnlyTest). */
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
