package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import runar.compiler.Cli;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;

/**
 * N-065 / N-060 — a user identifier spelled like a name the compiler mints is
 * refused, with one diagnostic shared verbatim by all seven tiers.
 *
 * <p>Before: {@code let t2: bigint = p; assert(p > 0n); if (c) { t2 = p; }
 * assert(t2 + 1n === 1n);} compiled to a script that accepts p = 1, c = false,
 * which the source rejects ({@code 0n} lowers to the ANF temp {@code t2} and
 * the final guard read the temp). The other minted families (stack-lowering
 * slots, FixedArray slots, auto-injected parameters) were accepted the same
 * way, and {@code --ir} accepted parameters, properties, bindings and
 * references named after stack lowering's own slots (N-060).
 *
 * <p>Proves: every source case of the shared corpus
 * ({@code conformance/negatives/reserved-names-cases.json}) is refused by
 * Validate with the shared sentence while its renamed twin compiles; a
 * stateless contract's own {@code txPreimage} parameter compiles; every
 * {@code --ir} case is refused by AnfLoader and the accepted IR compiles to
 * {@code 00ac}. Does not prove: the other tiers
 * ({@code conformance/negatives/reserved-names.test.ts} does) or the on-chain
 * effect.
 */
class N065ReservedNamesTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> corpus() throws Exception {
        Path p = Path.of("..", "..", "conformance", "negatives", "reserved-names-cases.json");
        return (Map<String, Object>) AnfLoader.parseJsonTree(Files.readString(p));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Map<String, Object> c, String group, String key) {
        return (List<Map<String, Object>>) ((Map<String, Object>) c.get(group)).get(key);
    }

    private static String compileIr(Object ir) {
        AnfProgram anf = AnfLoader.parse(Jcs.stringify(ir));
        anf = Cli.optimizeAnf(anf, true);
        return Emit.run(Peephole.run(StackLower.run(anf)));
    }

    @TestFactory
    Stream<DynamicTest> sourceCases() throws Exception {
        Map<String, Object> c = corpus();
        List<DynamicTest> tests = new ArrayList<>();
        for (Map<String, Object> k : list(c, "source", "cases")) {
            String name = (String) k.get("name");
            String file = (String) k.get("file");
            String error = (String) k.get("error");
            tests.add(DynamicTest.dynamicTest("refuses " + name, () -> {
                Validate.Result r = Validate.runCollecting(ParserDispatch.parse((String) k.get("src"), file));
                assertTrue(
                    r.errors().stream().anyMatch(e -> e.equals(error) || e.endsWith(": " + error)),
                    "want " + error + ", got " + r.errors());
            }));
            tests.add(DynamicTest.dynamicTest("compiles the twin of " + name, () ->
                PipelineTestSupport.hex((String) k.get("twin"), file)));
        }
        for (Map<String, Object> a : list(c, "source", "accept")) {
            tests.add(DynamicTest.dynamicTest("accepts " + a.get("name"), () ->
                PipelineTestSupport.hex((String) a.get("src"), (String) a.get("file"))));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> irCases() throws Exception {
        Map<String, Object> c = corpus();
        List<DynamicTest> tests = new ArrayList<>();
        for (Map<String, Object> k : list(c, "ir", "cases")) {
            String error = (String) k.get("error");
            tests.add(DynamicTest.dynamicTest("refuses ir " + k.get("name"), () -> {
                RuntimeException ex = assertThrows(RuntimeException.class,
                    () -> AnfLoader.parse(Jcs.stringify(k.get("ir"))));
                assertTrue(String.valueOf(ex.getMessage()).contains(error),
                    "want " + error + ", got " + ex.getMessage());
            }));
        }
        for (Map<String, Object> a : list(c, "ir", "accept")) {
            tests.add(DynamicTest.dynamicTest("accepts ir " + a.get("name"), () ->
                assertEquals("00ac", compileIr(a.get("ir")))));
        }
        assertFalse(tests.isEmpty());
        return tests.stream();
    }
}
