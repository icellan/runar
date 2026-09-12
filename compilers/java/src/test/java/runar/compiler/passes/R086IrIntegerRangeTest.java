package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.RawScript;
import runar.compiler.ir.stack.StackProgram;

/**
 * R-086 — {@link AnfLoader} decoded every integer-typed ANF field through
 * {@code Long.intValue()} / {@code BigInteger.intValue()}, which keeps the low
 * 32 bits and throws the rest away without a word. The {@code --ir} path takes
 * EXTERNALLY SUPPLIED IR, the same trust boundary R-079 and R-081 closed on the
 * Go tier, and the truncation was not cosmetic there:
 *
 * <pre>
 *   loop count  2^31     go REJECT (cap)   java accepted, emitted 00009c77
 *                                          — count wrapped to -2^31, loop body GONE
 *   loop count  2^32+5   go REJECT (cap)   java accepted, byte-identical to count=5
 *   loop count  -2^31-1  go REJECT (neg)   java wrapped to 2^31-1 and unrolled until
 *                                          OutOfMemoryError
 *   loop step   2^32+1   go accept         java accepted DIFFERENT SCRIPT BYTES
 *                        ...0501000000 01...   ...5152...  (step wrapped to 1)
 *   loop step   -2^31-1  go accept         java accepted DIFFERENT SCRIPT BYTES
 * </pre>
 *
 * <p>Two tiers accepting the same IR bytes and emitting different locking
 * scripts is the failure this suite exists to prevent, so the loader now
 * refuses any integer field it cannot represent, naming the field and the
 * value. That makes Java deliberately stricter than Go on {@code loop.step}
 * (Go's field is a 64-bit {@code int}, so it takes 2^31 happily) — stated here
 * rather than discovered later, in the same spirit as R-079's note.
 *
 * <p>{@code check_preimage.sighashFlag} was in the finding but is NOT a
 * divergence: Go masks with {@code & 0xff} before splicing the DER flag byte
 * (codegen/oppushtx.go:79), so Java's truncation produced identical bytes for
 * every probe. It is rejected here anyway because the range rule is one helper,
 * not nine special cases. {@code sourceLoc} truncation was real but debug-only
 * (line 4294967303 came back as 7 in the emitted source map).
 */
class R086IrIntegerRangeTest {

    /**
     * The {@code --ir} pipeline exactly as {@code Cli#compileIr} runs it:
     * load, optimize fold-OFF, lower, peephole, emit.
     */
    private static String hexFromIr(String json) {
        AnfProgram anf = AnfLoader.parse(json);
        anf = Cli.optimizeAnf(anf, /* disableConstantFolding */ true);
        StackProgram stack = StackLower.run(anf);
        stack = Peephole.run(stack);
        return Emit.run(stack);
    }

    /** A three-iteration loop summing the iterator; `%s` is count, `%s` is step. */
    private static final String LOOP_IR = """
        {"contractName":"L","properties":[{"name":"target","readonly":true,"type":"bigint"}],
         "methods":[{"name":"m","isPublic":true,"params":[],"body":[
           {"name":"t0","value":{"kind":"load_const","value":0}},
           {"name":"sum","value":{"kind":"load_const","value":"@ref:t0"}},
           {"name":"t5","value":{"kind":"loop","count":%s,"iterVar":"i","start":0,"step":%s,
             "body":[
               {"name":"t3","value":{"kind":"load_param","name":"i"}},
               {"name":"t4","value":{"kind":"bin_op","left":"sum","op":"+","right":"t3"}},
               {"name":"sum","value":{"kind":"load_const","value":"@ref:t4"}}]}},
           {"name":"t6","value":{"kind":"load_prop","name":"target"}},
           {"name":"t7","value":{"kind":"bin_op","left":"sum","op":"===","right":"t6"}},
           {"name":"t8","value":{"kind":"assert","value":"t7"}}]}]}
        """;

    private static final String SHELL = """
        {
          "contractName":"X",
          "properties":[],
          "methods":[
            {"name":"m","isPublic":true,"params":[],"body":[%s]}
          ]
        }
        """;

    private static AnfProgram parseShell(String body) {
        return AnfLoader.parse(SHELL.formatted(body));
    }

    // ------------------------------------------------------------------
    // Controls — the same shapes with in-range values must still load and
    // still emit the bytes they emitted before.
    // ------------------------------------------------------------------

    @Test
    void controlInRangeLoopCountAndStepStillEmitTheSameBytes() {
        // 0 + 1 + 2 == 3, and 0 + 2 + 4 == 6. Both checked against the Go
        // tier's `runar-go -ir ... -hex -disable-constant-folding`.
        assertEquals("53009c", hexFromIr(LOOP_IR.formatted("3", "1")));
        assertEquals("56009c", hexFromIr(LOOP_IR.formatted("3", "2")));
    }

    @Test
    void controlInRangeIntegerFieldsStillDecode() {
        AnfProgram p = parseShell(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"check_preimage\",\"preimage\":\"p\","
                + "\"sighashFlag\":67},"
                + "\"sourceLoc\":{\"file\":\"C.runar.ts\",\"line\":12,\"column\":4}},"
                + "{\"name\":\"t1\",\"value\":{\"kind\":\"raw_script\",\"bytes\":\"51\","
                + "\"in_arity\":0,\"out_arity\":1}}");
        CheckPreimage cp = (CheckPreimage) p.methods().get(0).body().get(0).value();
        assertEquals(67, cp.sighashFlag());
        assertEquals(12, p.methods().get(0).body().get(0).sourceLoc().line());
        RawScript rs = (RawScript) p.methods().get(0).body().get(1).value();
        assertEquals(0, rs.inArity());
        assertEquals(1, rs.outArity());
    }

    @Test
    void controlTheIntBoundariesThemselvesStillDecode() {
        // Integer.MIN_VALUE / MAX_VALUE are representable and must not be
        // swept up by the range check.
        AnfProgram p = parseShell(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"check_preimage\",\"preimage\":\"p\","
                + "\"sighashFlag\":-2147483648}}");
        assertEquals(Integer.MIN_VALUE,
            ((CheckPreimage) p.methods().get(0).body().get(0).value()).sighashFlag());

        Loop loop = (Loop) AnfLoader.parse(LOOP_IR.formatted("2147483647", "1"))
            .methods().get(0).body().get(2).value();
        assertEquals(Integer.MAX_VALUE, loop.count());
    }

    // ------------------------------------------------------------------
    // loop.count — the field whose truncation erased a loop body
    // ------------------------------------------------------------------

    @Test
    void rejectsLoopCountAboveIntRange() {
        // Would have wrapped to Integer.MIN_VALUE and emitted a script with
        // the loop body gone entirely.
        RuntimeException ex = assertThrows(RuntimeException.class,
            () -> AnfLoader.parse(LOOP_IR.formatted("2147483648", "1")));
        assertDiagnostic(ex, "loop count", "2147483648");
    }

    @Test
    void rejectsLoopCountThatWrapsIntoAValidLookingCount() {
        // 2^32 + 5 wrapped to 5 and compiled to exactly the bytes count=5
        // compiles to — a silently different loop bound.
        RuntimeException ex = assertThrows(RuntimeException.class,
            () -> AnfLoader.parse(LOOP_IR.formatted("4294967301", "1")));
        assertDiagnostic(ex, "loop count", "4294967301");
    }

    @Test
    void rejectsLoopCountBelowIntRange() {
        // Wrapped to Integer.MAX_VALUE and unrolled until the heap gave out.
        RuntimeException ex = assertThrows(RuntimeException.class,
            () -> AnfLoader.parse(LOOP_IR.formatted("-2147483649", "1")));
        assertDiagnostic(ex, "loop count", "-2147483649");
    }

    // ------------------------------------------------------------------
    // loop.step — the field where BOTH tiers accepted and the BYTES DIFFERED
    // ------------------------------------------------------------------

    @Test
    void rejectsLoopStepOutsideIntRange() {
        RuntimeException ex = assertThrows(RuntimeException.class,
            () -> AnfLoader.parse(LOOP_IR.formatted("3", "4294967297")));
        assertDiagnostic(ex, "loop step", "4294967297");

        RuntimeException neg = assertThrows(RuntimeException.class,
            () -> AnfLoader.parse(LOOP_IR.formatted("3", "-2147483649")));
        assertDiagnostic(neg, "loop step", "-2147483649");
    }

    // ------------------------------------------------------------------
    // remaining int-typed fields
    // ------------------------------------------------------------------

    @Test
    void rejectsRawScriptArityOutsideIntRange() {
        RuntimeException in = assertThrows(RuntimeException.class, () -> parseShell(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"raw_script\",\"bytes\":\"51\","
                + "\"in_arity\":4294967297,\"out_arity\":1}}"));
        assertDiagnostic(in, "raw_script in_arity", "4294967297");

        RuntimeException out = assertThrows(RuntimeException.class, () -> parseShell(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"raw_script\",\"bytes\":\"51\","
                + "\"in_arity\":0,\"out_arity\":-2147483649}}"));
        assertDiagnostic(out, "raw_script out_arity", "-2147483649");
    }

    @Test
    void rejectsSighashFlagOutsideIntRange() {
        RuntimeException ex = assertThrows(RuntimeException.class, () -> parseShell(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"check_preimage\",\"preimage\":\"p\","
                + "\"sighashFlag\":4294967363}}"));
        assertDiagnostic(ex, "check_preimage sighashFlag", "4294967363");
    }

    @Test
    void rejectsSourceLocOutsideIntRange() {
        RuntimeException ex = assertThrows(RuntimeException.class, () -> parseShell(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"load_prop\",\"name\":\"p\"},"
                + "\"sourceLoc\":{\"file\":\"C.runar.ts\",\"line\":4294967303,\"column\":4}}"));
        assertDiagnostic(ex, "sourceLoc line", "4294967303");
    }

    @Test
    void rejectsSyntheticArrayChainIndexOutsideIntRange() {
        RuntimeException ex = assertThrows(RuntimeException.class, () -> AnfLoader.parse("""
            {"contractName":"X",
             "properties":[{"name":"g__0","type":"bigint","readonly":false,
               "syntheticArrayChain":[{"base":"g","index":4294967297,"length":2}]}],
             "methods":[]}
            """));
        assertDiagnostic(ex, "syntheticArrayChain.index", "4294967297");
    }

    /**
     * A JSON float is not an integer. Go's {@code encoding/json} refuses to
     * unmarshal {@code 10000000000.0} into an {@code int}; Java's loader used
     * {@code Number.intValue()} here, which clamps a {@code Double} to
     * {@code Integer.MAX_VALUE} and carried on.
     */
    @Test
    void rejectsANonIntegerJsonNumberInAnIntField() {
        RuntimeException ex = assertThrows(RuntimeException.class, () -> AnfLoader.parse("""
            {"contractName":"X",
             "properties":[{"name":"g__0","type":"bigint","readonly":false,
               "syntheticArrayChain":[{"base":"g","index":1.5,"length":2}]}],
             "methods":[]}
            """));
        assertTrue(ex.getMessage().contains("syntheticArrayChain.index"),
            "expected the field name in: " + ex.getMessage());
    }

    private static void assertDiagnostic(RuntimeException ex, String field, String value) {
        String m = ex.getMessage();
        assertTrue(m != null && m.contains(field),
            "diagnostic must name the field '" + field + "', got: " + m);
        assertTrue(m.contains(value),
            "diagnostic must quote the offending value '" + value + "', got: " + m);
    }
}
