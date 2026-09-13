package runar.compiler.frontend;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R-182 (CL-BUG-062): {@code InputLimits.assertSourceBytesUnderLimit} returned
 * early on a null source instead of rejecting it.
 *
 * <p>The guard is the first thing {@link ParserDispatch#parse} runs, and its
 * job is to stop bad input BEFORE a format parser touches it. Returning on null
 * let the null through to the tokenizer, where it surfaced as a JVM message
 * wrapped in a ParseException. Measured before the fix, for every format:
 *
 * <pre>
 *   ParserDispatch.parse(null, "X.runar.ts") -&gt; ParseException:
 *       Cannot invoke "String.length()" because "source" is null
 * </pre>
 *
 * <p>That is a caller mistake reported as an internal error. The guard now
 * names it, and keeps reporting it as a ParseException so no caller's catch
 * block changes.
 */
class R182NullSourceTest {

    @Test
    void theSizeGuardRejectsNullInsteadOfPassingItThrough() {
        ParserDispatch.ParseException e = assertThrows(
            ParserDispatch.ParseException.class,
            () -> InputLimits.assertSourceBytesUnderLimit(null));
        assertNotNull(e.getMessage());
        assertTrue(
            e.getMessage().contains("null"),
            "the diagnostic must say the source was null; got: " + e.getMessage());
        assertTrue(
            !e.getMessage().contains("Cannot invoke"),
            "the diagnostic must not be a JVM NPE message; got: " + e.getMessage());
    }

    @Test
    void everyFormatReportsANullSourceTheSameWay() throws Exception {
        String[] names = {
            "X.runar.ts", "X.runar.sol", "X.runar.move", "X.runar.py",
            "X.runar.go", "X.runar.rs", "X.runar.zig", "X.runar.rb", "X.runar.java",
        };
        for (String name : names) {
            ParserDispatch.ParseException e = assertThrows(
                ParserDispatch.ParseException.class,
                () -> ParserDispatch.parse(null, name),
                name + " accepted a null source");
            assertTrue(
                !String.valueOf(e.getMessage()).contains("Cannot invoke"),
                name + " reported a JVM NPE message: " + e.getMessage());
        }
    }

    /** Control: the size guard still does what it is named for. */
    @Test
    void theSizeGuardStillAcceptsAndRejectsBySize() throws Exception {
        InputLimits.assertSourceBytesUnderLimit("");
        InputLimits.assertSourceBytesUnderLimit("class A {}");

        StringBuilder big = new StringBuilder(InputLimits.MAX_SOURCE_BYTES + 16);
        while (big.length() < InputLimits.MAX_SOURCE_BYTES + 8) big.append('a');
        InputLimits.SourceSizeExceededException e = assertThrows(
            InputLimits.SourceSizeExceededException.class,
            () -> InputLimits.assertSourceBytesUnderLimit(big.toString()));
        assertEquals(InputLimits.MAX_SOURCE_BYTES, e.limit());
        assertTrue(e.actual() > e.limit());
    }
}
