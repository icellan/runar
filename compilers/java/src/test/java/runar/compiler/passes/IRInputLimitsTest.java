package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.passes.IRInputLimits.IRNestingExceededException;
import runar.compiler.passes.IRInputLimits.IRSizeExceededException;

/**
 * BUG-008 follow-up: IR-loader size-guard regression tests.
 */
class IRInputLimitsTest {

    private static String repeat(char c, int n) {
        char[] a = new char[n];
        java.util.Arrays.fill(a, c);
        return new String(a);
    }

    @Test
    void loaderRejectsOversizedInput() {
        String oversized = repeat(' ', IRInputLimits.MAX_IR_BYTES + 1);
        IRSizeExceededException ex = assertThrows(
            IRSizeExceededException.class,
            () -> AnfLoader.parse(oversized)
        );
        assertEquals(IRInputLimits.MAX_IR_BYTES, ex.limit());
        assertEquals(IRInputLimits.MAX_IR_BYTES + 1, ex.actual());
    }

    @Test
    void loaderRejectsDeeplyNestedInput() {
        int depth = IRInputLimits.MAX_IR_NESTING + 50;
        StringBuilder sb = new StringBuilder("1");
        for (int i = 0; i < depth; i++) {
            sb.insert(0, "{\"n\":").append("}");
        }
        IRNestingExceededException ex = assertThrows(
            IRNestingExceededException.class,
            () -> AnfLoader.parse(sb.toString())
        );
        assertEquals(IRInputLimits.MAX_IR_NESTING, ex.limit());
    }

    /**
     * N-113: both fixtures below used to carry {@code "methods":[]}, which
     * R-081 established is not a valid program at all — it is the
     * anyone-can-spend shape (no public method =&gt; empty locking script =&gt;
     * spendable with OP_1). These tests' subject is the DoS caps, not the
     * schema, so the fixtures are made valid rather than the assertions
     * weakened.
     */
    private static final String MINIMAL_VALID_METHODS =
        "\"methods\":[{\"name\":\"unlock\",\"params\":[],\"isPublic\":true,\"body\":[]}]";

    @Test
    void depthWalkIgnoresBracesInsideStrings() {
        // 1000 `{` inside a JSON string MUST NOT count toward depth.
        String openBraces = repeat('{', 1000);
        String bad = "{\"contractName\":\"X\",\"properties\":[]," + MINIMAL_VALID_METHODS + ","
                + "\"_note\":\"" + openBraces + "\"}";
        // Should parse successfully; downstream loader returns a program.
        AnfProgram p = AnfLoader.parse(bad);
        assertNotNull(p);
    }

    @Test
    void loaderAcceptsMinimalProgram() {
        String minimal =
            "{\"contractName\":\"X\",\"properties\":[]," + MINIMAL_VALID_METHODS + "}";
        AnfProgram p = AnfLoader.parse(minimal);
        assertNotNull(p);
    }

    @Test
    void assertIRBytesUnderLimitTypedError() {
        IRSizeExceededException ex = assertThrows(
            IRSizeExceededException.class,
            () -> IRInputLimits.assertIRBytesUnderLimit(repeat('x', IRInputLimits.MAX_IR_BYTES + 1))
        );
        assertTrue(ex.getMessage().contains("MAX_IR_BYTES"));
    }
}
