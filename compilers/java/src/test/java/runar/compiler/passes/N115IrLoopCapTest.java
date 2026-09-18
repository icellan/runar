package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.Loop;

/**
 * N-115 — the unroll ceiling on the {@code --ir} path.
 *
 * <p>{@link Loop#MAX_LOOP_COUNT} (10000) has existed in this tier all along,
 * but the only thing that read it was {@link AnfLower} — the SOURCE path.
 * {@code AnfLoader.asInt} bounded the count to 32-bit signed range (R-086),
 * which is a strictly weaker claim: 10001 is a perfectly good {@code int}.
 *
 * <p>Measured against the checked-in {@code bounded-loop} golden: Go, Python
 * and Ruby rejected {@code count=10001}; Java, Rust and Zig accepted it and all
 * three emitted the SAME 199734-hexchar (~97 KB) script (sha256
 * {@code e2c1be39...}). Three tiers agreeing is indistinguishable from three
 * tiers being right to a gate that only diffs bytes, which is why this needed
 * a negative fixture —
 * {@code conformance/negatives/ir/I07-loop-count-over-max.ir.json}, that same
 * golden with this one field changed.
 */
class N115IrLoopCapTest {

    /**
     * A one-method contract parameterised on the loop count alone, so every
     * case below differs from the control in exactly one field.
     */
    private static String ir(long count) {
        return """
            {"contractName":"Bounded","properties":[],"methods":[
              {"name":"unlock","params":[],"isPublic":true,"body":[
                {"name":"t0","value":{"kind":"loop","count":%d,"iterVar":"i","body":[
                  {"name":"t1","value":{"kind":"load_const","value":0}}
                ]}}
              ]}
            ]}
            """.formatted(count);
    }

    /**
     * The control. A count exactly AT the limit is legal and must still load —
     * without this row, "rejects 10001" would be equally consistent with a
     * loader that had stopped accepting loops at all.
     */
    @Test
    void controlLoopCountAtTheLimitStillLoads() {
        AnfProgram p = AnfLoader.parse(ir(Loop.MAX_LOOP_COUNT));
        assertEquals("Bounded", p.contractName());
    }

    @Test
    void rejectsLoopCountOverMax() {
        RuntimeException ex = assertThrows(
            RuntimeException.class, () -> AnfLoader.parse(ir(Loop.MAX_LOOP_COUNT + 1L)));
        assertTrue(
            ex.getMessage().contains("loop count 10001 exceeding maximum 10000"),
            "diagnostic must name the count and the limit, as Go's does: " + ex.getMessage());
    }

    /**
     * The pre-existing R-086 range guard is the OUTER bound and still fires
     * first for a value no {@code int} can hold. Pinned here so a future edit
     * cannot reorder the two checks into one that silently narrows before
     * comparing.
     */
    @Test
    void anOutOf32BitRangeCountIsStillRejectedByTheRangeGuard() {
        RuntimeException ex = assertThrows(
            RuntimeException.class, () -> AnfLoader.parse(ir(8589934592L))); // 2^33
        assertTrue(
            ex.getMessage().contains("out of 32-bit signed range"), ex.getMessage());
    }
}
