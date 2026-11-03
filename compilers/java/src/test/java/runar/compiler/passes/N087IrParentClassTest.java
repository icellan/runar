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
 * N-087 — the {@code --ir} loader enforces the source validator's parentClass
 * rules and refuses a write to a readonly or undeclared property, with the
 * diagnostics shared by all seven tiers
 * ({@code conformance/negatives/ir-parent-class-cases.json}).
 *
 * <p>Before: a SmartContract declaring {@code owner} with readonly:false
 * (F-107's v2-mut-stateless) compiled to {@code 76767b8777}, which an
 * attacker's key spends under strict @bsv/sdk Spend; a readonly write, a
 * stateful-only node in a non-stateful contract and a raw_script outside
 * UnsafeSmartContract compiled too.
 *
 * <p>Proves: every corpus case is refused with its diagnostic and the accepted
 * programs (incl. parentClass-less IR) load. Does not prove that a declared
 * StatefulSmartContract body enforces its state continuation.
 */
class N087IrParentClassTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> corpus() throws Exception {
        Path p = Path.of("..", "..", "conformance", "negatives", "ir-parent-class-cases.json");
        return (Map<String, Object>) AnfLoader.parseJsonTree(Files.readString(p));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> group(String key) throws Exception {
        return (List<Map<String, Object>>) corpus().get(key);
    }

    @Test
    void acceptedProgramsLoad() throws Exception {
        for (Map<String, Object> a : group("accept")) {
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
            boolean prefix = "prefix".equals(c.get("match"));
            try {
                AnfLoader.parse(Jcs.stringify(c.get("ir")));
                failures.add(c.get("name") + ": accepted; want " + want);
            } catch (RuntimeException e) {
                String got = e.getMessage();
                if (prefix ? !got.startsWith(want) : !got.equals(want)) {
                    failures.add(c.get("name") + ": got " + got + "; want " + want);
                }
            }
        }
        if (!failures.isEmpty()) fail(failures.size() + " case(s) wrong:\n" + String.join("\n", failures));
    }
}
