package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.Loop;

/**
 * F-283 / CL-GAP-164 — the {@code --ir} loader bounds each loop's iteration
 * count individually ({@link Loop#MAX_LOOP_COUNT}, N-115) but, before this
 * fix, never the PRODUCT across nested loops.
 *
 * <p>Two loop bindings of {@code MAX_LOOP_COUNT} each, one nested inside the
 * other, each independently pass the per-binding check even though the real
 * unrolled iteration count is {@code MAX_LOOP_COUNT x MAX_LOOP_COUNT} =
 * 100,000,000 -- a count that, if this IR ever reached stack lowering,
 * drives the unroller into multi-GB memory growth (measured upstream, Ruby
 * tier, same shape: a 1,175-byte payload loaded in 0.0s and then drove
 * compile_from_ir to 5m07s / 3.7GB RSS and climbing).
 *
 * <p>What this proves: {@code AnfLoader.parse} rejects a nested-loop IR
 * whose counts each individually satisfy {@code MAX_LOOP_COUNT} but whose
 * product does not, with a diagnostic naming the total, before any
 * lowering pass sees the program.
 * <p>What this does not prove: that stack lowering itself would be safe
 * against such a product if it arrived some other way -- only that this
 * loader-level route is closed.
 */
class F283IrLoopProductBoundTest {

    /**
     * A one-method contract with two nested {@code loop} bindings,
     * parameterised on both counts. N-071: the body ends with
     * {@code _ok = true; assert(_ok)}.
     */
    private static String ir(long outerCount, long innerCount) {
        return """
            {"contractName":"Bounded","properties":[],"methods":[
              {"name":"unlock","params":[],"isPublic":true,"body":[
                {"name":"outer","value":{"kind":"loop","count":%d,"iterVar":"i","body":[
                  {"name":"inner","value":{"kind":"loop","count":%d,"iterVar":"j","body":[
                    {"name":"t0","value":{"kind":"load_const","value":0}}
                  ]}}
                ]}},{"name":"_ok","value":{"kind":"load_const","value":true}},{"name":"_ok_assert","value":{"kind":"assert","value":"_ok"}}
              ]}
            ]}
            """.formatted(outerCount, innerCount);
    }

    /**
     * Control: nested loops whose product stays within MAX_LOOP_COUNT must
     * still load -- the new check must not be a disguised depth limit.
     */
    @Test
    void controlNestedLoopProductWithinMaxStillLoads() {
        AnfProgram p = AnfLoader.parse(ir(10, 10));
        assertEquals("Bounded", p.contractName());
    }

    /**
     * The hostile case: {@code MAX_LOOP_COUNT x MAX_LOOP_COUNT}, each
     * individually within the per-binding ceiling, product 100,000,000 far
     * over it.
     */
    @Test
    void rejectsNestedLoopsWhoseProductExceedsMax() {
        RuntimeException ex = assertThrows(
            RuntimeException.class,
            () -> AnfLoader.parse(ir(Loop.MAX_LOOP_COUNT, Loop.MAX_LOOP_COUNT)));
        assertTrue(
            ex.getMessage().contains("100000000"),
            "diagnostic must name the total iteration count: " + ex.getMessage());
    }

    /**
     * Neither 101 nor 100 alone trips the per-binding ceiling (both are far
     * below MAX_LOOP_COUNT), but their product (10,100) does. Proves the new
     * rule is the product, not a disguised re-check of the single bound.
     */
    @Test
    void rejectsSmallNestedCountsWhoseProductExceedsMax() {
        RuntimeException ex = assertThrows(
            RuntimeException.class, () -> AnfLoader.parse(ir(101, 100)));
        assertTrue(
            ex.getMessage().contains("10100"),
            "diagnostic must name the total iteration count: " + ex.getMessage());
    }
}
