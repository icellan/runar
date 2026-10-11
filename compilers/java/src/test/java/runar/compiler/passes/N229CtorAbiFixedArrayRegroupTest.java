package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;

/**
 * N-229: the Java artifact assembler must regroup synthetic {@code FixedArray}
 * CONSTRUCTOR-PARAM leaves into one {@code abi.constructor.params} entry, the
 * way every other tier's assembler does ({@code compilers/go/compiler/compiler.go}
 * {@code ctorEntries}/{@code assembleArtifact}, equivalently the TS reference's
 * {@code extractABI}/{@code regroupSyntheticRuns} in
 * {@code packages/runar-compiler/src/artifact/assembler.ts}).
 *
 * <p>N-086 ({@link N086ArtifactStateFieldRegroupTest}) fixed this for
 * {@code stateFields} via {@code StateFieldRegroup#run}; before THIS fix the
 * sibling {@code StateFieldRegroup#runCtor} path did not exist and
 * {@code Cli#writeArtifact} published a FixedArray constructor parameter's
 * expanded leaves ({@code table__0..table__3}) as four independent scalar
 * {@code abi.constructor.params} entries instead of one
 * {@code fixedArray}-tagged entry.
 *
 * <h2>Why a crafted {@code --ir} input, not a source fixture</h2>
 * Every one of the nine source frontends REFUSES a {@code FixedArray}
 * constructor parameter at validation time (TS: {@code 02-validate.ts}
 * {@code "Constructor parameter '...' cannot be a FixedArray"}; every other
 * tier ports the same rule) — a readonly or mutable {@code FixedArray}
 * property with no compile-time initializer can only reach the artifact
 * assembler through a hand-built ANF IR (no source path can express it, the
 * same reason {@code conformance/tests/fixed-array-index}'s own {@code table}
 * property carries a {@code = [10,20,30,40]} initializer and so is NOT a
 * constructor param there). This test derives that IR from the real
 * {@code fixed-array-index} golden by dropping the {@code initialValue} the
 * expand-fixed-arrays pass would never have attached in the first place —
 * same four leaves, same {@code syntheticArrayChain}, but now deploy-time
 * (constructor-supplied) instead of baked in.
 *
 * <p>Expected shape is the Go reference compiler's output for the same IR
 * ({@code ./compilers/go/runar-go --ir <this IR>}):
 * {@code {"name":"table","type":"FixedArray<bigint, 4>","fixedArray":
 * {"elementType":"bigint","length":4,"syntheticNames":
 * ["table__0","table__1","table__2","table__3"]}}}.
 *
 * <h2>What these tests prove</h2>
 * <ul>
 *   <li>A constructor-supplied {@code FixedArray<bigint, 4>} regroups into one
 *       {@code abi.constructor.params} entry carrying
 *       {@code fixedArray.syntheticNames}, matching the Go reference.</li>
 *   <li>{@code constructorSlots} (the deploy-time byte-splice addresses) are
 *       UNCHANGED by the regroup — still one flat slot per expanded scalar
 *       leaf (paramIndex 0..3) — because the SDK splices into those slots by
 *       the flat pre-regroup property order ({@code 05-stack-lower.ts}
 *       equivalently {@code compilers/go/codegen/stack.go}'s {@code
 *       lowerLoadProp}), which this fix does not and must not touch. Only the
 *       user-facing ABI view is regrouped.</li>
 * </ul>
 *
 * <h2>What these tests do NOT prove</h2>
 * <ul>
 *   <li>Spendability. Nothing here broadcasts or runs the resulting script;
 *       that is the integration / SDK suites' job.</li>
 *   <li>That any real source program can trigger this path — by construction,
 *       none can (see above); the gap was only reachable via {@code --ir}.</li>
 * </ul>
 */
class N229CtorAbiFixedArrayRegroupTest {

    /**
     * {@code conformance/tests/fixed-array-index}'s golden ANF IR, with the
     * {@code initialValue} stripped from each {@code table__N} leaf so the
     * property is deploy-time (constructor-supplied) instead of baked in —
     * the only way a FixedArray constructor param reaches the assembler (see
     * class javadoc). Nothing else in the IR changes: same contract, same
     * method bodies, same {@code syntheticArrayChain} markers.
     */
    private static Path irWithoutTableInitialValues() throws Exception {
        Path golden = Path.of("..", "..", "conformance", "tests", "fixed-array-index", "expected-ir.json");
        assertTrue(Files.exists(golden), "missing fixture " + golden.toAbsolutePath());
        String text = Files.readString(golden);
        String stripped = text.replaceAll("\"initialValue\":\\s*\\d+,\\s*", "");
        assertTrue(stripped.length() < text.length(), "expected to strip at least one initialValue field");
        // The golden declares exactly 4 initialValue occurrences (one per
        // table__N leaf) and nowhere else; a different count means the
        // golden changed shape and this test's premise needs re-checking.
        long removed = text.split("\"initialValue\":", -1).length - 1;
        assertEquals(4, removed, "expected exactly 4 initialValue occurrences (table__0..table__3) in the golden");

        Path out = Files.createTempFile("runar-n229-ir-no-init", ".json");
        Files.writeString(out, stripped);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> artifactFrom(String... args) throws Exception {
        Path out = Files.createTempFile("runar-n229-artifact", ".json");
        try {
            String[] full = new String[args.length + 2];
            System.arraycopy(args, 0, full, 0, args.length);
            full[args.length] = "--emit-artifact";
            full[args.length + 1] = out.toString();
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int exit = new Cli(
                new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8))
                .run(full);
            assertEquals(0, exit, "runar-java CLI failed: " + stderr.toString(StandardCharsets.UTF_8));
            String body = Files.readString(out);
            return (Map<String, Object>) AnfLoader.parseJsonTree(body);
        } finally {
            Files.deleteIfExists(out);
        }
    }

    private static Map<String, Object> obj(Object v, String context) {
        assertTrue(v instanceof Map, context + " must be a JSON object, got " + v);
        return (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> constructorParams(Map<String, Object> artifact) {
        Map<String, Object> abi = obj(artifact.get("abi"), "artifact.abi");
        Map<String, Object> ctor = obj(abi.get("constructor"), "artifact.abi.constructor");
        Object params = ctor.get("params");
        assertNotNull(params, "abi.constructor has no params");
        assertTrue(params instanceof List, "abi.constructor.params must be a JSON array");
        return (List<Object>) params;
    }

    /** Matches {@code ./compilers/go/runar-go --ir <this IR>}'s {@code abi.constructor.params[0]}. */
    private static Map<String, Object> expectedTableParam() {
        Map<String, Object> fixedArray = new LinkedHashMap<>();
        fixedArray.put("elementType", "bigint");
        fixedArray.put("length", 4L);
        fixedArray.put("syntheticNames", List.of("table__0", "table__1", "table__2", "table__3"));

        Map<String, Object> param = new LinkedHashMap<>();
        param.put("name", "table");
        param.put("type", "FixedArray<bigint, 4>");
        param.put("fixedArray", fixedArray);
        return param;
    }

    @Test
    void fixedArrayConstructorParamRegroupsIntoOneAbiEntry() throws Exception {
        Path ir = irWithoutTableInitialValues();
        try {
            Map<String, Object> artifact = artifactFrom("--ir", ir.toString());
            List<Object> params = constructorParams(artifact);
            assertEquals(1, params.size(), "table must regroup into exactly one constructor param; got " + params);
            assertEquals(expectedTableParam(), params.get(0),
                "grouped constructor param must match the Go reference (ctorEntries)");
        } finally {
            Files.deleteIfExists(ir);
        }
    }

    /**
     * The regroup is a published-ABI-view transform only: the deploy-time
     * splice addresses (one per expanded scalar leaf, assigned over the FLAT
     * pre-regroup property list by {@code StackLower}/{@code Emit}) must stay
     * exactly as many and in the same order regardless of how the ABI groups
     * them for display — matching the live Go binary's
     * {@code constructorSlots} for the same IR.
     */
    @Test
    @SuppressWarnings("unchecked")
    void constructorSlotsStayFlatDespiteAbiRegrouping() throws Exception {
        Path ir = irWithoutTableInitialValues();
        try {
            Map<String, Object> artifact = artifactFrom("--ir", ir.toString());
            Object slotsObj = artifact.get("constructorSlots");
            assertNotNull(slotsObj, "artifact has no constructorSlots");
            assertTrue(slotsObj instanceof List, "constructorSlots must be a JSON array");
            List<Object> slots = (List<Object>) slotsObj;
            assertEquals(4, slots.size(), "four scalar leaves must still mean four flat slots; got " + slots);
            for (int i = 0; i < 4; i++) {
                Map<String, Object> slot = obj(slots.get(i), "constructorSlots[" + i + "]");
                assertEquals((long) i, slot.get("paramIndex"),
                    "constructorSlots[" + i + "].paramIndex must index the flat pre-regroup property list");
            }
        } finally {
            Files.deleteIfExists(ir);
        }
    }
}
