package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.SwapOp;

/**
 * Direct unit tests for the Java WOTS+ codegen module. Mirrors the
 * Python reference in {@code compilers/python/runar_compiler/codegen/stack.py}
 * (functions {@code _lower_verify_wots} and {@code _emit_wots_one_chain}).
 *
 * <p>The emitted opcode sequence is byte-identical across all compiler tiers;
 * a divergence here would surface as a conformance-runner mismatch but a unit
 * test catches it locally.
 *
 * <p>Algorithm structure (from the Python/Go/Rust references):
 *
 * <ul>
 *   <li>Each WOTS+ chain emits a 15-iteration unrolled loop, each iteration
 *       containing a single IF/ELSE block with 2 branches. So 1 chain → 15 IFs.</li>
 *   <li>{@code emitVerifyWots} calls {@code emitWotsOneChain} 67 times
 *       (32 message bytes × 2 nibbles + 3 checksum digits). So
 *       67 × 15 = 1005 IFs total (recursively, ignoring nesting).</li>
 *   <li>Each chain ends with one OP_ADD and one OP_CAT.</li>
 *   <li>The verifier ends with OP_SHA256, OP_FROMALTSTACK, OP_EQUAL, then a
 *       cleanup SwapOp + DropOp.</li>
 * </ul>
 */
class WotsTest {

    private static List<StackOp> captureFullVerifier() {
        List<StackOp> ops = new ArrayList<>();
        Wots.emitVerifyWots(ops::add);
        return ops;
    }

    /** Recursively count opcode occurrences (descends into IfOp branches). */
    private static int countOpcodeDeep(List<StackOp> ops, String code) {
        int n = 0;
        for (StackOp op : ops) {
            if (op instanceof OpcodeOp o && o.code().equals(code)) n++;
            if (op instanceof IfOp i) {
                if (i.thenBranch() != null) n += countOpcodeDeep(i.thenBranch(), code);
                if (i.elseBranch() != null) n += countOpcodeDeep(i.elseBranch(), code);
            }
        }
        return n;
    }

    private static int countIfOpsDeep(List<StackOp> ops) {
        int n = 0;
        for (StackOp op : ops) {
            if (op instanceof IfOp i) {
                n++;
                if (i.thenBranch() != null) n += countIfOpsDeep(i.thenBranch());
                if (i.elseBranch() != null) n += countIfOpsDeep(i.elseBranch());
            }
        }
        return n;
    }

    @Test
    void verifyWotsEmitsLargeScript() {
        List<StackOp> ops = captureFullVerifier();
        // The verifier is roughly ~10 KB of script. Top-level op count is
        // dominated by 67 chains × 71 ops + verifier scaffolding.
        // Don't assert an exact count here — that's the conformance runner's
        // job — but assert it's clearly in the right ballpark (>4000 ops).
        assertTrue(ops.size() > 4000,
            "Expected verifyWOTS to emit thousands of ops, got " + ops.size());
    }

    @Test
    void verifyWotsContains1005IfBlocks() {
        // 67 chains × 15-iteration unrolled loop × 1 IF per iteration.
        // This is the single most diagnostic count: a regression in the chain
        // generator (off-by-one in the loop bound, dropped chain, etc.) shows
        // up here immediately.
        List<StackOp> ops = captureFullVerifier();
        assertEquals(67 * 15, countIfOpsDeep(ops),
            "verifyWOTS must emit exactly 1005 IF blocks (67 chains × 15 iters)");
    }

    @Test
    void verifyWotsContains67OpAdds() {
        // Each chain emits exactly one OP_ADD (csum += steps_copy).
        List<StackOp> ops = captureFullVerifier();
        assertEquals(67, countOpcodeDeep(ops, "OP_ADD"),
            "verifyWOTS must emit exactly 67 OP_ADD (one per chain)");
    }

    @Test
    void verifyWotsContainsExpectedSha256Count() {
        // Each chain has 15 OP_SHA256 inside the ELSE branch (one per iter).
        // Plus 2 outer SHA256 calls (msg hash + final pubkey reconstruction).
        // Total: 67 × 15 + 2 = 1007.
        List<StackOp> ops = captureFullVerifier();
        assertEquals(67 * 15 + 2, countOpcodeDeep(ops, "OP_SHA256"),
            "verifyWOTS must emit 67×15+2=1007 OP_SHA256 ops");
    }

    @Test
    void verifyWotsHeaderMatchesReference() {
        // Reference (Python _lower_verify_wots):
        //   push(32) OP_SPLIT OP_TOALTSTACK OP_ROT OP_ROT swap OP_SHA256 ...
        List<StackOp> ops = captureFullVerifier();
        assertTrue(ops.get(0) instanceof PushOp, "verifyWOTS first op is push(32)");
        assertTrue(ops.get(1) instanceof OpcodeOp s && "OP_SPLIT".equals(s.code()),
            "verifyWOTS second op is OP_SPLIT");
        assertTrue(ops.get(2) instanceof OpcodeOp t && "OP_TOALTSTACK".equals(t.code()),
            "verifyWOTS third op is OP_TOALTSTACK");
        assertTrue(ops.get(3) instanceof OpcodeOp r && "OP_ROT".equals(r.code()),
            "verifyWOTS fourth op is OP_ROT");
        assertTrue(ops.get(4) instanceof OpcodeOp r2 && "OP_ROT".equals(r2.code()),
            "verifyWOTS fifth op is OP_ROT");
        assertTrue(ops.get(5) instanceof SwapOp,
            "verifyWOTS sixth op is SwapOp");
        assertTrue(ops.get(6) instanceof OpcodeOp h && "OP_SHA256".equals(h.code()),
            "verifyWOTS seventh op is OP_SHA256 (msg hash)");
    }

    @Test
    void verifyWotsTrailerMatchesReference() {
        // Reference trailer (last 6 ops):
        //   OP_SHA256 OP_FROMALTSTACK OP_EQUAL SwapOp DropOp
        List<StackOp> ops = captureFullVerifier();
        int n = ops.size();
        assertTrue(ops.get(n - 5) instanceof OpcodeOp s && "OP_SHA256".equals(s.code()),
            "verifyWOTS 5th-from-last is OP_SHA256");
        assertTrue(ops.get(n - 4) instanceof OpcodeOp f && "OP_FROMALTSTACK".equals(f.code()),
            "verifyWOTS 4th-from-last is OP_FROMALTSTACK");
        assertTrue(ops.get(n - 3) instanceof OpcodeOp e && "OP_EQUAL".equals(e.code()),
            "verifyWOTS 3rd-from-last is OP_EQUAL");
        assertTrue(ops.get(n - 2) instanceof SwapOp,
            "verifyWOTS 2nd-from-last is SwapOp");
        assertTrue(ops.get(n - 1) instanceof DropOp,
            "verifyWOTS last is DropOp");
    }

    @Test
    void isWotsBuiltinAcceptsKnownName() {
        assertTrue(Wots.isWotsBuiltin("verifyWOTS"));
    }

    @Test
    void isWotsBuiltinRejectsUnknown() {
        assertEquals(false, Wots.isWotsBuiltin("verifyWots"));
        assertEquals(false, Wots.isWotsBuiltin("verifyWOTSPlus"));
        assertEquals(false, Wots.isWotsBuiltin(""));
    }

    @Test
    void dispatchRoutesKnownName() {
        List<StackOp> ops = new ArrayList<>();
        Wots.dispatch("verifyWOTS", ops::add);
        assertTrue(ops.size() > 4000);
    }

    @Test
    void dispatchRejectsUnknownName() {
        assertThrows(RuntimeException.class, () -> Wots.dispatch("verifyFoo", op -> {}));
    }

    @Test
    void chainStructureIsConsistentAcrossInvocations() {
        // Calling emitVerifyWots() twice must produce the same ops (no
        // hidden state, no time-dependent behavior).
        List<StackOp> first = new ArrayList<>();
        Wots.emitVerifyWots(first::add);
        List<StackOp> second = new ArrayList<>();
        Wots.emitVerifyWots(second::add);
        assertEquals(first.size(), second.size());
        assertEquals(first, second,
            "emitVerifyWots must be deterministic — same input, same output");
    }
}
