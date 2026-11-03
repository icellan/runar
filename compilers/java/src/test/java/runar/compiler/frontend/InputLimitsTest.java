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

    // N-136: the nine per-format `XParser.parse` static entry points are
    // public API, called directly by tests/tooling and the Java SDK's
    // CompileCheck in some paths, and bypassed the size guard, which lived
    // only in ParserDispatch.parse. Each entry went straight to its own
    // tokenizer, so a caller invoking e.g. SolParser.parse or JavaParser.parse
    // directly got no DoS-bound rejection at all. This proves each of the 9
    // exported entries refuses a MAX_SOURCE_BYTES+1 input (by throwing that
    // format's own ParseException with a MAX_SOURCE_BYTES message); it does
    // not prove the guard runs before tokenization (code inspection only).
    @Test
    void everyExportedPerFormatParserRejectsOversizedInputDirectly() {
        String oversized = oversized();

        SolParser.ParseException sol = assertThrows(
            SolParser.ParseException.class,
            () -> SolParser.parse(oversized, "Counter.runar.sol"));
        assertTrue(sol.getMessage().contains("MAX_SOURCE_BYTES"));

        MoveParser.ParseException move = assertThrows(
            MoveParser.ParseException.class,
            () -> MoveParser.parse(oversized, "Counter.runar.move"));
        assertTrue(move.getMessage().contains("MAX_SOURCE_BYTES"));

        GoParser.ParseException go = assertThrows(
            GoParser.ParseException.class,
            () -> GoParser.parse(oversized, "Counter.runar.go"));
        assertTrue(go.getMessage().contains("MAX_SOURCE_BYTES"));

        RustParser.ParseException rust = assertThrows(
            RustParser.ParseException.class,
            () -> RustParser.parse(oversized, "Counter.runar.rs"));
        assertTrue(rust.getMessage().contains("MAX_SOURCE_BYTES"));

        PyParser.ParseException py = assertThrows(
            PyParser.ParseException.class,
            () -> PyParser.parse(oversized, "Counter.runar.py"));
        assertTrue(py.getMessage().contains("MAX_SOURCE_BYTES"));

        RbParser.ParseException rb = assertThrows(
            RbParser.ParseException.class,
            () -> RbParser.parse(oversized, "Counter.runar.rb"));
        assertTrue(rb.getMessage().contains("MAX_SOURCE_BYTES"));

        ZigParser.ParseException zig = assertThrows(
            ZigParser.ParseException.class,
            () -> ZigParser.parse(oversized, "Counter.runar.zig"));
        assertTrue(zig.getMessage().contains("MAX_SOURCE_BYTES"));

        TsParser.ParseException ts = assertThrows(
            TsParser.ParseException.class,
            () -> TsParser.parse(oversized, "Counter.runar.ts"));
        assertTrue(ts.getMessage().contains("MAX_SOURCE_BYTES"));

        JavaParser.ParseException java = assertThrows(
            JavaParser.ParseException.class,
            () -> JavaParser.parse(oversized, "Counter.runar.java"));
        assertTrue(java.getMessage().contains("MAX_SOURCE_BYTES"));
    }

    // Control for the above: a small input, well under the cap, must not
    // trip the guard on any entry point. Each parser is free to fail
    // afterwards for its own syntactic reasons -- this only asserts no
    // MAX_SOURCE_BYTES diagnostic was raised.
    @Test
    void everyExportedPerFormatParserAcceptsSmallInputAtTheGuard() {
        String small = "";

        assertSizeGuardDoesNotFire(() -> SolParser.parse(small, "Counter.runar.sol"));
        assertSizeGuardDoesNotFire(() -> MoveParser.parse(small, "Counter.runar.move"));
        assertSizeGuardDoesNotFire(() -> GoParser.parse(small, "Counter.runar.go"));
        assertSizeGuardDoesNotFire(() -> RustParser.parse(small, "Counter.runar.rs"));
        assertSizeGuardDoesNotFire(() -> PyParser.parse(small, "Counter.runar.py"));
        assertSizeGuardDoesNotFire(() -> RbParser.parse(small, "Counter.runar.rb"));
        assertSizeGuardDoesNotFire(() -> ZigParser.parse(small, "Counter.runar.zig"));
        assertSizeGuardDoesNotFire(() -> TsParser.parse(small, "Counter.runar.ts"));
        assertSizeGuardDoesNotFire(() -> JavaParser.parse(small, "Counter.runar.java"));
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static void assertSizeGuardDoesNotFire(ThrowingRunnable r) {
        try {
            r.run();
        } catch (Exception e) {
            assertFalse(
                e.getMessage() != null && e.getMessage().contains("MAX_SOURCE_BYTES"),
                "size guard incorrectly tripped on small input: " + e.getMessage());
        }
    }
}
