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
 * N-086: the Java artifact assembler must regroup synthetic FixedArray state
 * leaves into one {@code stateFields} entry, the way every other tier's
 * assembler does ({@code packages/runar-compiler/src/artifact/assembler.ts}
 * {@code extractStateFields}/{@code regroupSyntheticRuns}, ported verbatim to
 * {@code compilers/go/compiler/regroup.go}).
 *
 * <p>Before this test {@link Cli#run} published every expanded leaf
 * ({@code table__0}..{@code table__3}, or {@code grid__0__0}..{@code grid__1__1})
 * as its OWN scalar {@code stateFields} entry, on both the {@code --source} and
 * the {@code --ir} path — reachable because {@code AnfProperty} already carries
 * {@code syntheticArrayChain} (N-095 wire data) but {@code Cli#writeArtifact}
 * never read it. The SDKs read {@code stateFields} to build the user-facing
 * {@code state} map, so a Java-built artifact was not interchangeable with the
 * other six tiers': callers saw N raw scalar fields instead of one
 * {@code bigint[]} / {@code bigint[][]}.
 *
 * <p>Expected shapes are the Go reference compiler's output for the same
 * fixtures ({@code compilers/go/runar-go --source <file>}), which is also what
 * the TS assembler produces (modulo TS-only byte-layout annotations
 * {@code encoding}/{@code byteLength}/{@code byteOffset}/{@code tailOffset}
 * that neither Go nor Java emit).
 *
 * <h2>What these tests prove</h2>
 * <ul>
 *   <li>A single mutable {@code FixedArray<bigint, 4>} regroups into one
 *       {@code stateFields} entry carrying {@code fixedArray.syntheticNames},
 *       on both {@code --source} and {@code --ir}, and the two paths agree.</li>
 *   <li>A nested {@code FixedArray<FixedArray<bigint, 2>, 2>} regroups through
 *       two passes into one entry whose {@code elementType} is itself a
 *       {@code FixedArray<...>} string, a flat 4-name {@code syntheticNames}
 *       list, and a nested {@code [[0,0],[0,0]]} {@code initialValue}.</li>
 *   <li>The embedded {@code anf.properties} (present on every stateful
 *       artifact) still carries the four expanded leaves with their
 *       {@code syntheticArrayChain} — regrouping the published ABI/state view
 *       must not touch the lowering IR downstream passes consume.</li>
 * </ul>
 *
 * <h2>What these tests do NOT prove</h2>
 * <ul>
 *   <li>The constructor ABI ({@code abi.constructor.params}) — that was a
 *       sibling gap at the time of this fix, not part of N-086's testable
 *       assertion (stateFields only). It is now covered separately by
 *       {@code StateFieldRegroup#runCtor} and
 *       {@code N229CtorAbiFixedArrayRegroupTest}.</li>
 *   <li>Spendability. Nothing here broadcasts or runs the resulting script;
 *       that is the integration / SDK suites' job.</li>
 * </ul>
 */
class N086ArtifactStateFieldRegroupTest {

    @SuppressWarnings("unchecked")
    private static List<Object> stateFields(Map<String, Object> artifact) {
        Object sf = artifact.get("stateFields");
        assertNotNull(sf, "artifact has no stateFields");
        assertTrue(sf instanceof List, "stateFields must be a JSON array");
        return (List<Object>) sf;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> artifactFrom(String... args) throws Exception {
        Path out = Files.createTempFile("runar-n086-artifact", ".json");
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

    /**
     * The expected single-level grouped entry for {@code table: FixedArray<bigint, 4> = [0,0,0,0]}
     * (fixtures: {@code examples/ts/fixed-array-write/ArrayWrite.runar.ts},
     * {@code conformance/tests/fixed-array-write/expected-ir.json}). Matches
     * {@code ./compilers/go/runar-go --source examples/ts/fixed-array-write/ArrayWrite.runar.ts}.
     */
    private static Map<String, Object> expectedTableField() {
        Map<String, Object> fixedArray = new LinkedHashMap<>();
        fixedArray.put("elementType", "bigint");
        fixedArray.put("length", 4L);
        fixedArray.put("syntheticNames", List.of("table__0", "table__1", "table__2", "table__3"));

        Map<String, Object> field = new LinkedHashMap<>();
        field.put("name", "table");
        field.put("type", "FixedArray<bigint, 4>");
        field.put("index", 0L);
        field.put("initialValue", List.of(0L, 0L, 0L, 0L));
        field.put("fixedArray", fixedArray);
        return field;
    }

    @Test
    void arrayWriteViaSourceRegroupsIntoOneFixedArrayStateField() throws Exception {
        Path source = Path.of("..", "..", "examples", "ts", "fixed-array-write", "ArrayWrite.runar.ts");
        assertTrue(Files.exists(source), "missing fixture " + source.toAbsolutePath());

        Map<String, Object> artifact = artifactFrom("--source", source.toString());
        List<Object> fields = stateFields(artifact);
        assertEquals(1, fields.size(), "table must regroup into exactly one stateFields entry; got " + fields);
        assertEquals(expectedTableField(), fields.get(0), "grouped stateFields entry must match the Go reference");
    }

    @Test
    void arrayWriteViaIrGoldenRegroupsIntoOneFixedArrayStateFieldAndAgreesWithSource() throws Exception {
        Path ir = Path.of("..", "..", "conformance", "tests", "fixed-array-write", "expected-ir.json");
        assertTrue(Files.exists(ir), "missing golden IR " + ir.toAbsolutePath());

        Map<String, Object> viaIr = artifactFrom("--ir", ir.toString());
        List<Object> irFields = stateFields(viaIr);
        assertEquals(1, irFields.size(), "table must regroup into exactly one stateFields entry; got " + irFields);
        assertEquals(expectedTableField(), irFields.get(0), "grouped stateFields entry must match the Go reference");

        Path source = Path.of("..", "..", "examples", "ts", "fixed-array-write", "ArrayWrite.runar.ts");
        Map<String, Object> viaSource = artifactFrom("--source", source.toString());
        assertEquals(stateFields(viaSource), irFields,
            "--source and --ir must agree on the regrouped stateFields (R-007 F-038 round trip)");
    }

    /**
     * The embedded ANF (present because ArrayWrite is a StatefulSmartContract)
     * must keep the four RAW expanded leaves with their chain — regrouping the
     * published view is purely a view over {@code anf.properties}, it must not
     * rewrite the lowering IR every downstream pass already consumed.
     */
    @Test
    @SuppressWarnings("unchecked")
    void arrayWriteEmbeddedAnfStillCarriesTheFourExpandedLeaves() throws Exception {
        Path source = Path.of("..", "..", "examples", "ts", "fixed-array-write", "ArrayWrite.runar.ts");
        Map<String, Object> artifact = artifactFrom("--source", source.toString());
        Object anf = artifact.get("anf");
        assertNotNull(anf, "stateful artifact must embed anf");
        List<Object> props = (List<Object>) obj(anf, "anf").get("properties");
        assertEquals(4, props.size(), "embedded anf.properties must keep the 4 expanded leaves; got " + props);
        for (int i = 0; i < 4; i++) {
            Map<String, Object> p = obj(props.get(i), "anf.properties[" + i + "]");
            assertEquals("table__" + i, p.get("name"));
            assertNotNull(p.get("syntheticArrayChain"), "leaf " + i + " must keep its syntheticArrayChain");
        }
    }

    /**
     * Nested case: {@code grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0,0],[0,0]]}
     * (fixture: {@code examples/ts/fixed-array-nested/Grid2x2.v2.runar.ts}). The
     * regrouper must run twice (once per nesting level) to collapse the four
     * leaves into one entry whose {@code elementType} is itself a
     * {@code FixedArray<bigint, 2>} string. Matches
     * {@code ./compilers/go/runar-go --source examples/ts/fixed-array-nested/Grid2x2.v2.runar.ts}.
     */
    @Test
    void grid2x2NestedFixedArrayRegroupsThroughTwoLevelsIntoOneStateField() throws Exception {
        Path source = Path.of("..", "..", "examples", "ts", "fixed-array-nested", "Grid2x2.v2.runar.ts");
        assertTrue(Files.exists(source), "missing fixture " + source.toAbsolutePath());

        Map<String, Object> artifact = artifactFrom("--source", source.toString());
        List<Object> fields = stateFields(artifact);
        assertEquals(1, fields.size(), "grid must regroup into exactly one stateFields entry; got " + fields);

        Map<String, Object> field = obj(fields.get(0), "stateFields[0]");
        assertEquals("grid", field.get("name"));
        assertEquals("FixedArray<FixedArray<bigint, 2>, 2>", field.get("type"));
        assertEquals(0L, field.get("index"));
        assertEquals(List.of(List.of(0L, 0L), List.of(0L, 0L)), field.get("initialValue"),
            "nested initialValue must mirror the declared [[0,0],[0,0]] shape");

        Map<String, Object> fixedArray = obj(field.get("fixedArray"), "stateFields[0].fixedArray");
        assertEquals("FixedArray<bigint, 2>", fixedArray.get("elementType"),
            "elementType must itself be the inner FixedArray<...> string");
        assertEquals(2L, fixedArray.get("length"));
        assertEquals(List.of("grid__0__0", "grid__0__1", "grid__1__0", "grid__1__1"), fixedArray.get("syntheticNames"),
            "syntheticNames must be the flat leaf list in declaration order");
    }
}
