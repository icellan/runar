package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-095 — the synthetic-array chain on {@code AnfProperty} is wire data.
 *
 * <p>The expand-fixed-arrays pass desugars a {@code FixedArray} property into
 * scalar siblings and hangs a chain of {@code {base, index, length}} levels off
 * each leaf. Every other tier's artifact assembler regroups those siblings back
 * into a single FixedArray state/ABI entry by reading that chain off the ANF
 * PROGRAM, not off the AST. So an ANF that loses the field still compiles to
 * byte-identical script while the SDK's {@code state.grid} accessor degrades
 * into four raw {@code grid__i__j} scalars.
 *
 * <p>Java's {@code AnfProperty} carried no such component at all, so
 * {@code --emit-ir} dropped the chain entirely. That is a cross-tier defect
 * even though Java itself has no regrouper: an ANF Java emits is fed to every
 * other tier's {@code --ir}, and none of them could recover the regrouping
 * from it.
 *
 * <p><b>Deliberately out of scope here:</b> Java does not regroup
 * {@code stateFields} in EITHER mode — it has no port of the Go assembler's
 * {@code regroupStateFields}, as {@code Cli#writeArtifact}'s "Known gaps"
 * javadoc says. That is a separate, pre-existing defect. This test pins the
 * WIRE only: Java must write the chain and read it back under the settled
 * spelling, so the other six tiers can regroup Java's ANF.
 */
class N095SyntheticArrayChainTest {

    private static final String GRID_SRC = """
        import { StatefulSmartContract, assert } from 'runar-lang';
        import type { FixedArray } from 'runar-lang';

        export class Grid2x2 extends StatefulSmartContract {
          grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

          constructor() {
            super();
          }

          public set00(v: bigint) {
            this.grid[0][0] = v;
            assert(true);
          }

          public set11(v: bigint) {
            this.grid[1][1] = v;
            assert(true);
          }
        }
        """;

    private static final String SCALAR_SRC = """
        import { StatefulSmartContract, assert } from 'runar-lang';

        export class Counter extends StatefulSmartContract {
          count: bigint = 0n;

          constructor() {
            super();
          }

          public increment() {
            this.count = this.count + 1n;
            assert(true);
          }
        }
        """;

    private static AnfProgram lower(String src, String fileName) throws Exception {
        ContractNode contract = ParserDispatch.parse(src, fileName);
        assertNotNull(contract, "parse produced no contract");
        return AnfLower.run(ExpandFixedArrays.run(contract));
    }

    /** The canonical ANF JSON {@code --emit-ir} prints. */
    private static String emitIr(String src, String fileName) throws Exception {
        return Jcs.stringify(lower(src, fileName));
    }

    // -----------------------------------------------------------------
    // Wire format
    // -----------------------------------------------------------------

    @Test
    void emitIrWritesTheChainUnderTheSettledSpelling() throws Exception {
        String ir = emitIr(GRID_SRC, "Grid2x2.runar.ts");

        assertTrue(ir.contains("\"syntheticArrayChain\""),
            "--emit-ir dropped the synthetic-array chain, so no other tier can regroup Java's ANF");
        assertFalse(ir.contains("\"__syntheticArrayChain\""), "AST-marker spelling on the wire");
        assertFalse(ir.contains("\"synthetic_array_chain\""), "snake spelling on the wire");

        // Four leaves, each with a two-level chain rooted at `grid`.
        assertEquals(4, countOccurrences(ir, "\"syntheticArrayChain\""));
        assertEquals(8, countOccurrences(ir, "\"base\""));
        assertEquals(4, countOccurrences(ir, "\"base\":\"grid\""));
    }

    @Test
    void everyEmittedPropertyKeyIsDeclaredInTheSharedSchema() throws Exception {
        Path schemaPath = Path.of("..", "..", "packages", "runar-ir-schema", "src", "schemas",
            "anf-ir.schema.json");
        String schema = Files.readString(schemaPath);

        // `$defs.ANFProperty` is additionalProperties:false, so anything Java
        // writes outside its declared key set fails validateANF.
        int defIdx = schema.indexOf("\"ANFProperty\"");
        assertTrue(defIdx >= 0, "$defs.ANFProperty missing from the shared ANF schema");
        String def = schema.substring(defIdx, schema.indexOf("\"ANFMethod\"", defIdx));
        assertTrue(def.contains("\"additionalProperties\": false"),
            "$defs.ANFProperty is no longer additionalProperties:false — this test's premise "
                + "(an undeclared key is a schema violation) no longer holds");

        for (String key : propertyKeys(emitIr(GRID_SRC, "Grid2x2.runar.ts"))) {
            assertTrue(def.contains('"' + key + '"'),
                "emitted ANFProperty key \"" + key + "\" is not declared in $defs.ANFProperty");
        }
    }

    /** Byte-neutrality control: a FixedArray-free contract must not grow the key. */
    @Test
    void scalarPropertyCarriesNoChain() throws Exception {
        String ir = emitIr(SCALAR_SRC, "Counter.runar.ts");
        assertFalse(ir.contains("ynthetic"),
            "a FixedArray-free contract grew a synthetic-array key: " + ir);
    }

    // -----------------------------------------------------------------
    // Loader readback — the half that makes Java a usable --ir consumer
    // -----------------------------------------------------------------

    @Test
    void loaderRecoversTheChainFromOurOwnAnf() throws Exception {
        AnfProgram loaded = AnfLoader.parse(emitIr(GRID_SRC, "Grid2x2.runar.ts"));

        assertEquals(4, loaded.properties().size());
        int[][] want = {{0, 0}, {0, 1}, {1, 0}, {1, 1}};
        for (int i = 0; i < loaded.properties().size(); i++) {
            AnfProperty p = loaded.properties().get(i);
            List<AnfProperty.SyntheticArrayLevel> chain = p.syntheticArrayChain();
            assertNotNull(chain, "leaf " + i + ": the loader dropped the chain");
            assertEquals(2, chain.size(), "leaf " + i + ": a 2x2 grid nests twice");
            assertEquals("grid", chain.get(0).base());
            assertEquals(want[i][0], chain.get(0).index());
            assertEquals(2, chain.get(0).length());
            assertEquals(want[i][1], chain.get(1).index());
            assertEquals(2, chain.get(1).length());
        }
    }

    /** Loading an ANF and re-emitting it must be a fixed point on the wire. */
    @Test
    void chainSurvivesLoadAndReEmit() throws Exception {
        String first = emitIr(GRID_SRC, "Grid2x2.runar.ts");
        String second = Jcs.stringify(AnfLoader.parse(first));
        assertEquals(first, second, "--emit-ir -> --ir -> --emit-ir is not a fixed point");
    }

    @Test
    void scalarPropertyLoadsWithNoChain() throws Exception {
        for (AnfProperty p : AnfLoader.parse(emitIr(SCALAR_SRC, "Counter.runar.ts")).properties()) {
            assertNull(p.syntheticArrayChain(), "a FixedArray-free property grew a chain on load");
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static int countOccurrences(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + 1)) n++;
        return n;
    }

    /** Every JSON key appearing inside the top-level {@code "properties"} array. */
    private static Set<String> propertyKeys(String ir) {
        int start = ir.indexOf("\"properties\":[");
        assertTrue(start >= 0, "no properties array in the emitted ANF");
        int depth = 0;
        int i = start + "\"properties\":".length();
        int end = i;
        for (; end < ir.length(); end++) {
            char c = ir.charAt(end);
            if (c == '[') depth++;
            else if (c == ']') {
                depth--;
                if (depth == 0) break;
            }
        }
        String slice = ir.substring(i, end + 1);
        Set<String> keys = new LinkedHashSet<>();
        Matcher m = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]*)\"\\s*:").matcher(slice);
        while (m.find()) keys.add(m.group(1));
        // The chain's own level keys are described by $defs.ANFSyntheticArrayLevel.
        keys.removeAll(Set.of("base", "index", "length"));
        return keys;
    }
}
