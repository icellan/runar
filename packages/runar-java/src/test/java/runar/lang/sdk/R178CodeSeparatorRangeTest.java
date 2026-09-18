package runar.lang.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R-178 (CL-BUG-071): the three sites that trimmed a subscript at the
 * OP_CODESEPARATOR each wrote {@code scriptHex.substring((codeSepIdx + 1) * 2)},
 * which throws StringIndexOutOfBoundsException when the offset is past the end
 * — a fund-moving signature path reporting a bad input as a JVM internal error.
 *
 * <p>All seven SDKs mishandled this, in four different ways: rust, python, ruby
 * and zig signed the UNTRIMMED subscript; ts signed an EMPTY one (String.slice
 * past the end returns ''); go panicked on the slice; java threw here. Every
 * tier now refuses and names the input.
 */
class R178CodeSeparatorRangeTest {

    /** Two bytes: OP_CODESEPARATOR then OP_1. Offset 1 is the last valid index. */
    private static final String SUBSCRIPT = "ab51";

    @Test
    void anOutOfRangeIndexIsRefusedWithADiagnosis() {
        for (int idx : new int[] {2, 3, 99}) {
            IllegalArgumentException e = assertThrows(
                IllegalArgumentException.class,
                () -> RunarContract.subscriptAfterCodeSep(SUBSCRIPT, idx),
                "codeSeparatorIndex " + idx + " past the end was accepted");
            assertTrue(
                e.getMessage().contains("codeSeparatorIndex"),
                "the refusal must name the offending input; got: " + e.getMessage());
            assertTrue(
                !e.getMessage().contains("begin 0, end"),
                "the refusal must not be a raw substring error; got: " + e.getMessage());
        }
    }

    @Test
    void inRangeIndicesStillTrim() {
        assertEquals("51", RunarContract.subscriptAfterCodeSep(SUBSCRIPT, 0));
        assertEquals("", RunarContract.subscriptAfterCodeSep(SUBSCRIPT, 1));
    }
}
