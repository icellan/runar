package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.InputLimits.SourceSizeExceededException;

/**
 * BUG-008 follow-up: source-parser size-guard regression tests.
 */
class InputLimitsTest {

    private static String oversized() {
        char[] chars = new char[InputLimits.MAX_SOURCE_BYTES + 1];
        java.util.Arrays.fill(chars, ' ');
        return new String(chars);
    }

    @Test
    void assertSourceBytesUnderLimitRejectsOversizedInput() {
        SourceSizeExceededException ex = assertThrows(
            SourceSizeExceededException.class,
            () -> InputLimits.assertSourceBytesUnderLimit(oversized())
        );
        assertEquals(InputLimits.MAX_SOURCE_BYTES, ex.limit());
        assertEquals(InputLimits.MAX_SOURCE_BYTES + 1, ex.actual());
        assertTrue(ex.getMessage().contains("MAX_SOURCE_BYTES"));
    }

    @Test
    void assertSourceBytesUnderLimitAcceptsAtLimit() throws Exception {
        char[] chars = new char[InputLimits.MAX_SOURCE_BYTES];
        java.util.Arrays.fill(chars, ' ');
        // == limit is accepted; cap is strict > only.
        InputLimits.assertSourceBytesUnderLimit(new String(chars));
    }

    @Test
    void parserDispatchRejectsOversizedAcrossAllExtensions() {
        String oversized = oversized();
        for (String ext : new String[] {
            ".runar.ts", ".runar.sol", ".runar.move", ".runar.go",
            ".runar.py", ".runar.rs", ".runar.rb", ".runar.zig", ".runar.java"
        }) {
            SourceSizeExceededException ex = assertThrows(
                SourceSizeExceededException.class,
                () -> ParserDispatch.parse(oversized, "Counter" + ext)
            );
            assertEquals(InputLimits.MAX_SOURCE_BYTES, ex.limit());
        }
    }

    @Test
    void parserDispatchDoesNotTripSizeGuardOnNormalSource() {
        // A minimal source that is well under the cap. We don't care
        // whether the format-specific parser succeeds; only that the
        // size guard does NOT fire.
        String src = "// short source\n";
        try {
            ParserDispatch.parse(src, "Counter.runar.ts");
        } catch (SourceSizeExceededException e) {
            assertFalse(true, "size guard incorrectly tripped: " + e.getMessage());
        } catch (Exception e) {
            // Other parser errors are fine.
        }
    }
}
