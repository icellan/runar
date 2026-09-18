package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for CL-BUG-088 / R-009: nothing bounded the magnitude of an
 * unrolled loop's iteration count on the SOURCE path, in any tier.
 *
 * <p>This tier was the only one that failed loudly on an out-of-range bound —
 * {@code BigInteger.intValueExact()} throws rather than truncating, which is the
 * behaviour the other six adopted as the reference. What it did NOT have is a
 * ceiling: {@code MAX_LOOP_COUNT} (10000) lived only in the Go tier's
 * {@code --ir} loader, so a loop written in source could ask for any count an
 * {@code int} can hold. A bound of 10001 compiled happily, and a large in-range
 * one would have wedged the unroller outright while every narrowing check
 * reported "in range".
 *
 * <p>What these tests pin: an out-of-range or over-ceiling loop bound is a
 * compile-time diagnostic naming the loop, and a valid loop still compiles to
 * the exact bytes it produced before the ceiling existed.
 */
class LoopBoundNarrowingTest {

    /**
     * Watchdog for a single compile. A bound an {@code int} can hold (10^6)
     * drives unbounded unrolling, which no assertion can interrupt from the test
     * thread — so the compile runs on its own thread and a regression fails fast
     * instead of wedging CI. Mirrors the Go tier's goroutine-behind-a-watchdog
     * in {@code bigint_narrowing_guard_test.go}.
     */
    private static final Duration WATCHDOG = Duration.ofSeconds(30);

    private static String loopBoundSource(String bound) {
        return """
            import { SmartContract, assert } from 'runar-lang';

            export class LoopBound extends SmartContract {
              constructor() { super(); }

              public unlock(x: bigint): void {
                let acc: bigint = 0n;
                for (let i = 0n; i < BOUNDn; i++) {
                  acc = acc + i;
                }
                assert(acc === x);
              }
            }"""
            .replace("BOUND", bound);
    }

    /** Compile behind the watchdog; returns the hex, or the diagnostic message. */
    private record Outcome(String hex, String error) {
        boolean rejected() {
            return error != null;
        }
    }

    private static Outcome compileGuarded(String bound) {
        return assertTimeoutPreemptively(WATCHDOG, () -> {
            try {
                return new Outcome(
                    PipelineTestSupport.hex(loopBoundSource(bound), "LoopBound.runar.ts"), null);
            } catch (Exception e) {
                String msg = e.getMessage();
                return new Outcome(null, msg == null ? e.toString() : msg);
            }
        }, "bound " + bound + " did not produce a result within " + WATCHDOG
            + " — the unbounded count is still driving loop unrolling");
    }

    private static void assertRejected(Outcome outcome, String label) {
        if (!outcome.rejected()) {
            fail("bound " + label + ": expected a compile diagnostic, got a successful compile "
                + "(script " + outcome.hex() + ")");
        }
        assertTrue(outcome.error().toLowerCase().contains("loop"),
            "bound " + label + ": expected a diagnostic mentioning the loop bound, got: "
                + outcome.error());
    }

    /**
     * Control: a normal small bound must keep compiling, and to the exact bytes
     * it produced before the ceiling was added. If a guard moves these, the
     * guard is not byte-neutral and the change is a codegen regression, not a
     * fix. The hexes are the seven-tier agreed output.
     */
    @Test
    void controlStillCompilesByteIdentically() throws Exception {
        for (String[] tc : List.of(new String[] {"3", "537c9c"}, new String[] {"10", "012d7c9c"})) {
            for (boolean disableFolding : List.of(false, true)) {
                assertEquals(tc[1],
                    PipelineTestSupport.hex(loopBoundSource(tc[0]), "LoopBound.runar.ts", disableFolding),
                    "bound=" + tc[0] + " foldOff=" + disableFolding + ": script hex changed");
            }
        }
    }

    @Test
    void bound2Pow63IsRejected() {
        assertRejected(compileGuarded("9223372036854775808"), "2^63");
    }

    @Test
    void bound2Pow64Plus10IsRejected() {
        Outcome outcome = compileGuarded("18446744073709551626");
        // Belt and braces: whatever happens, it must not silently agree with the
        // `i < 10n` contract the way the modular-wrap tiers did.
        assertNotEquals("012d7c9c", outcome.hex());
        assertRejected(outcome, "2^64+10");
    }

    @Test
    void bound10Pow20IsRejected() {
        assertRejected(compileGuarded("100000000000000000000"), "10^20");
    }

    /**
     * The ceiling half of the fix. 10001 and 10^6 both fit an {@code int}, so no
     * amount of narrowing care stops them — only MAX_LOOP_COUNT on the SOURCE
     * path does. The watchdog above is what makes the 10^6 case safe to run.
     */
    @Test
    void boundExceedingMaxLoopCountIsRejectedOnSourcePath() {
        for (String bound : List.of("10001", "1000000")) {
            Outcome outcome = compileGuarded(bound);
            assertRejected(outcome, bound);
            assertTrue(outcome.error().contains("10000"),
                "bound " + bound + ": expected the diagnostic to name the maximum loop count, got: "
                    + outcome.error());
        }
    }
}
