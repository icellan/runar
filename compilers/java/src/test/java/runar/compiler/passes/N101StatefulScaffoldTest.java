package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.canonical.Jcs;

/**
 * N-101 — the {@code --ir} loader refuses a StatefulSmartContract program
 * (declared, or inferred per N-087) any of whose public methods lacks,
 * reorders or alters the scaffolding ANF lowering injects (auto-injected
 * parameters, the checkPreimage / sighash / deserialize_state prologue, the
 * state continuation), with the diagnostics shared by all seven tiers
 * ({@code conformance/negatives/ir-stateful-scaffold-cases.json}).
 *
 * <p>Before: F-107's attack body relabelled StatefulSmartContract compiled to
 * {@code 76767b8777}, which an attacker's key spends under strict @bsv/sdk
 * Spend, and so did the parentClass-less variant carrying a dead
 * add_data_output.
 *
 * <p>Proves: every corpus case is refused with its exact diagnostic and the
 * accepted programs (incl. unmodified stateful goldens) load. Does not prove
 * cross-tier agreement (conformance/negatives/ir-stateful-scaffold.test.ts
 * does) or anything about the free user code between prologue and
 * continuation.
 */
class N101StatefulScaffoldTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> corpus() throws Exception {
        Path p = Path.of("..", "..", "conformance", "negatives", "ir-stateful-scaffold-cases.json");
        return (Map<String, Object>) AnfLoader.parseJsonTree(Files.readString(p));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> group(String key) throws Exception {
        return (List<Map<String, Object>>) corpus().get(key);
    }

    @Test
    void acceptedProgramsLoad() throws Exception {
        List<Map<String, Object>> accept = group("accept");
        assertTrue(accept.size() >= 3);
        for (Map<String, Object> a : accept) {
            AnfLoader.parse(Jcs.stringify(a.get("ir")));
        }
    }

    @Test
    void everyCaseRefusedWithSharedDiagnostic() throws Exception {
        List<Map<String, Object>> cases = group("cases");
        assertTrue(cases.size() >= 10);
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> c : cases) {
            String want = (String) c.get("error");
            try {
                AnfLoader.parse(Jcs.stringify(c.get("ir")));
                failures.add(c.get("name") + ": accepted; want " + want);
            } catch (RuntimeException e) {
                if (!want.equals(e.getMessage())) {
                    failures.add(c.get("name") + ": got " + e.getMessage() + "; want " + want);
                }
            }
        }
        if (!failures.isEmpty()) fail(failures.size() + " case(s) wrong:\n" + String.join("\n", failures));
    }
}
