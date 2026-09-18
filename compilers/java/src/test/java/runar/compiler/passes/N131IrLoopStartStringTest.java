package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.stack.StackProgram;

/**
 * N-131 follow-up — a {@code loop.start} written as an {@code "<decimal>n"}
 * string is legal ANF IR, and this tier was the only one refusing it.
 *
 * <p>The schema is explicit. {@code anf-ir.schema.json}:
 *
 * <pre>
 *   Loop.start   {"oneOf": [{"type": "integer"}, {"type": "string"}]}
 * </pre>
 *
 * <p>The string arm exists because a loop start can exceed a tier's native
 * integer (issue #121), and the {@code n}-suffixed decimal string is the
 * project's sanctioned encoding for exactly that — the same one
 * {@code load_const.value} and {@code ANFProperty.initialValue} already use,
 * both of which THIS loader already accepts as strings. {@code loop.start}
 * was the one place the arm was missing: {@code AnfLoader.asBigInt} took
 * {@code BigInteger}, {@code Long} and {@code Integer} and threw on anything
 * else.
 *
 * <p>Measured on the checked-in {@code bounded-loop} golden with
 * {@code start} set to {@code "0n"}, each tier's own {@code --ir} entry point,
 * classified by exit code:
 *
 * <pre>
 *   go=0  rust=0  python=0  zig=0  ruby=0   java=65
 *   java: runar-java: ir parse error: expected integer, got class java.lang.String
 * </pre>
 *
 * <p>The five that accept agree byte-for-byte with each other AND with the
 * integer-start control, so {@code "0n"} already means {@code 0} everywhere it
 * is honoured. That is the property the tests below assert: not merely that
 * the string form loads, but that it lowers to the SAME script as the integer
 * it denotes. A loader that accepted the string and read it as something else
 * would pass a "does it load" test and still put a number in a locking script
 * that the IR did not contain.
 *
 * <h2>Why only the {@code n}-suffixed form</h2>
 *
 * <p>Deliberately narrow, because the peers do NOT agree outside it. Measured
 * on the same golden, same entry points:
 *
 * <pre>
 *   "5n"   go 5 · rust 5 · python 5 · zig 5 · ruby 5      unanimous
 *   "-3n"  all five agree                                  unanimous
 *   "5"    go 5 · python 5 · zig 5 · ruby 5 · RUST 0        SPLIT
 *   "abc"  go reject · python reject · rust 0 · zig 0 · ruby 0   SPLIT
 *   ""     go reject · python reject · rust 0 · zig 0 · ruby 0   SPLIT
 *   "5nn"  go reject · python reject · rust 0 · zig 0 · ruby 0   SPLIT
 *   "999999999999999999999999999999n"
 *          go/rust/python/ruby one script · ZIG a different one  SPLIT
 * </pre>
 *
 * <p>{@code "0"} without the suffix looks unanimous — all five emit the
 * start-0 script — but that is a coincidence: three of them reach 0 by
 * FALLING BACK to 0 on a string they could not parse, which {@code "5"}
 * exposes. So the suffix-less form is a split too, and every split above stays
 * refused here. Java refusing an input its peers disagree about is the safe
 * side of that line: it cannot silently invent a loop start.
 */
class N131IrLoopStartStringTest {

    /**
     * The {@code bounded-loop} shape, parameterised on the {@code start} token
     * alone so each case differs from its control in exactly one JSON token.
     * The token is spliced in raw, so a caller passes {@code "0"} for the
     * integer form and {@code "\"0n\""} for the string form.
     */
    private static String ir(String startToken) {
        return """
            {"contractName":"Bounded","properties":[],"methods":[
              {"name":"unlock","params":[],"isPublic":true,"body":[
                {"name":"t0","value":{"kind":"loop","count":3,"start":%s,"step":1,"iterVar":"i","body":[
                  {"name":"t1","value":{"kind":"load_const","value":0}}
                ]}}
              ]}
            ]}
            """.formatted(startToken);
    }

    /** The CLI's own {@code --ir ... --hex} pipeline, minus the process. */
    private static String hexOf(String json) {
        AnfProgram anf = AnfLoader.parse(json);
        StackProgram stack = StackLower.run(anf);
        return Emit.run(Peephole.run(stack));
    }

    // -----------------------------------------------------------------
    // the gate
    // -----------------------------------------------------------------

    @Test
    void loopStartAsDecimalStringLoadsAndMeansTheIntegerItDenotes() {
        assertEquals(hexOf(ir("0")), hexOf(ir("\"0n\"")));
    }

    @Test
    void aNonZeroDecimalStringStartMeansThatNumber() {
        // The case "0n" cannot prove on its own: 0 is also what every
        // fallback-to-zero path produces, so a loader that ignored the string
        // entirely would pass the test above.
        assertEquals(hexOf(ir("5")), hexOf(ir("\"5n\"")));
    }

    @Test
    void aNegativeDecimalStringStartMeansThatNumber() {
        assertEquals(hexOf(ir("-3")), hexOf(ir("\"-3n\"")));
    }

    // -----------------------------------------------------------------
    // controls — the integer arm must be untouched
    // -----------------------------------------------------------------

    @Test
    void controlIntegerStartStillLoads() {
        AnfProgram p = AnfLoader.parse(ir("5"));
        assertEquals("Bounded", p.contractName());
    }

    @Test
    void controlAbsentStartStillLoadsAsZero() {
        String noStart = """
            {"contractName":"Bounded","properties":[],"methods":[
              {"name":"unlock","params":[],"isPublic":true,"body":[
                {"name":"t0","value":{"kind":"loop","count":3,"step":1,"iterVar":"i","body":[
                  {"name":"t1","value":{"kind":"load_const","value":0}}
                ]}}
              ]}
            ]}
            """;
        assertEquals(hexOf(ir("0")), hexOf(noStart));
    }

    // -----------------------------------------------------------------
    // the splits stay refused
    // -----------------------------------------------------------------

    @Test
    void aStringStartWithoutTheSuffixIsStillRefused() {
        // "5" reads as 5 in go/python/zig/ruby and as 0 in rust. There is no
        // majority answer to adopt, so this tier keeps refusing rather than
        // picking one.
        RuntimeException ex = assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir("\"5\"")));
        assertTrue(
            ex.getMessage().contains("loop start"),
            "diagnostic should name the field, got: " + ex.getMessage()
        );
    }

    @Test
    void anUnparseableStringStartIsStillRefused() {
        RuntimeException ex = assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir("\"abc\"")));
        assertTrue(
            ex.getMessage().contains("loop start"),
            "diagnostic should name the field, got: " + ex.getMessage()
        );
    }

    @Test
    void anEmptyStringStartIsStillRefused() {
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir("\"\"")));
    }

    @Test
    void aDoubleSuffixStringStartIsStillRefused() {
        // "5nn" — the suffix stripper must strip ONE `n` and then require the
        // remainder to be a decimal, not strip greedily.
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir("\"5nn\"")));
    }

    @Test
    void aBareSuffixStringStartIsStillRefused() {
        // "n" strips to the empty string, which is not a decimal.
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir("\"n\"")));
    }

    @Test
    void aFloatShapedStringStartIsStillRefused() {
        // N-131 refuses a JSON float outright. The string form must not become
        // a way back in for one.
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir("\"1.5n\"")));
    }
}
