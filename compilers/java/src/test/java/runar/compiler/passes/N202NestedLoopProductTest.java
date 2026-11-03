package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * N-202: the source path bounds the PRODUCT of nested loop counts, not just
 * each loop's own count.
 *
 * <p>{@code extractLoopShape} caps one for-loop at {@code MAX_LOOP_COUNT}
 * (10,000). Two loops of 9,000, one inside the other, each passed that cap while
 * the unrolled work was 81,000,000 iterations. F-283 refuses the same nest on
 * the {@code --ir} path, so a source contract compiled while its own emitted IR
 * was refused on replay.
 *
 * <p>Proves: on the Java source path a 101 x 100 nest is refused with the shared
 * product diagnostic, also when the inner loop sits in an if arm, and a nest of
 * exactly 10,000 still compiles. Each compile runs behind a preemptive watchdog,
 * so a regression fails instead of hanging.
 *
 * <p>Does not prove: the other tiers
 * ({@code conformance/negatives/n202-nested-loop-product-parity.test.ts}), or
 * loops reached through a private method call that stack lowering inlines later
 * — the bound is per-method nesting in ANF, the same rule the {@code --ir}
 * loader applies.
 */
class N202NestedLoopProductTest {

    private static final Duration WATCHDOG = Duration.ofSeconds(60);

    private static final String PRODUCT_DIAG =
        "For loop unrolls to 100 iterations nested inside an enclosing loop of total count 101, "
            + "producing 10100 total iterations, exceeding the maximum loop count of 10000.";

    private static String nestedLoopSource(int outer, int inner, boolean inIfArm) {
        String innerLoop = "for (let j = 0n; j < " + inner + "n; j++) { acc = acc + x; }";
        if (inIfArm) {
            innerLoop = "if (x > 0n) { " + innerLoop + " }";
        }
        return """
            import { SmartContract, assert } from 'runar-lang';

            export class NestedLoops extends SmartContract {
              constructor() { super(); }

              public unlock(x: bigint): void {
                let acc: bigint = 0n;
                for (let i = 0n; i < OUTERn; i++) { INNER }
                assert(acc > x);
              }
            }"""
            .replace("OUTER", Integer.toString(outer))
            .replace("INNER", innerLoop);
    }

    /** Compile behind the watchdog; returns the diagnostic message, or null on success. */
    private static String compileGuarded(String source) {
        return assertTimeoutPreemptively(WATCHDOG, () -> {
            try {
                PipelineTestSupport.hex(source, "NestedLoops.runar.ts");
                return null;
            } catch (Exception e) {
                String msg = e.getMessage();
                return msg == null ? e.toString() : msg;
            }
        }, "compile did not finish within " + WATCHDOG
            + " — nested loops are being unrolled unbounded");
    }

    @Test
    void nestedLoopProductOverMaxIsRejected() {
        for (boolean inIfArm : new boolean[] {false, true}) {
            String error = compileGuarded(nestedLoopSource(101, 100, inIfArm));
            assertNotNull(error, "inIfArm=" + inIfArm + ": expected the 101 x 100 nest to be refused");
            assertTrue(error.contains(PRODUCT_DIAG),
                "inIfArm=" + inIfArm + ": expected diagnostic " + PRODUCT_DIAG + ", got: " + error);
        }
    }

    @Test
    void nestedLoopProductAtMaxStillCompiles() {
        assertNull(compileGuarded(nestedLoopSource(100, 100, false)));
    }
}
