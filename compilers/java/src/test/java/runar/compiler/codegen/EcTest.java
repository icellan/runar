package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.BigIntPushValue;
import runar.compiler.ir.stack.ByteStringPushValue;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.NipOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PickOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.RollOp;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.SwapOp;
import runar.compiler.passes.Emit;

/**
 * Byte-identical parity tests for {@link Ec} against the Python and TS
 * reference codegen.
 *
 * <p>Expected op counts and byte-lengths were captured by running the
 * Python reference ({@code compilers/python/runar_compiler/codegen/ec.py})
 * on the same commit as this port.
 *
 * <p>R-052 / CL-BUG-095, the Point WIDTH gate, moved these goldens. A
 * {@code Point} is 64 bytes by definition and nothing checked it, so a surplus
 * byte was split off and silently dropped: {@code ecOnCurve(G || 0xff)} returned
 * TRUE and {@code ecEncodeCompressed} took its parity bit from the caller's
 * extra byte. The deltas are all structural, which is what makes them match the
 * six other tiers byte-for-byte:
 *
 * <ul>
 *   <li>+3 per {@code decomposePoint} call site — OP_SIZE, push 64,
 *       OP_NUMEQUALVERIFY. {@code ecAdd} decomposes TWICE, hence +6;
 *       {@code ecMul} / {@code ecMulGen} / {@code ecNegate} once.</li>
 *   <li>+15 {@code ecOnCurve} — 9 for the clamp-and-flag gate (it must stay a
 *       PREDICATE and answer {@code false}, not abort, or
 *       {@code if (ecOnCurve(p))} stops being writable), +3 for the
 *       {@code decomposePoint} gate, +1 for the extra OP_BOOLAND folding
 *       {@code _len_ok} in, +2 for rolling the two flags up.</li>
 *   <li>+3 {@code ecPointX} / {@code ecPointY}.</li>
 * </ul>
 *
 * <p>{@code ecEncodeCompressed} stays at 16 ops and that is NOT an oversight:
 * the gate adds 3 ops while the fixed-offset parity read (push 31, OP_SPLIT,
 * OP_NIP) replaces a 6-op OP_SIZE/OP_SUB/OP_SPLIT/OP_SWAP/OP_DROP sequence with
 * 3. Net zero ops, +2 bytes (push 64 is a 2-byte push, push 1 was 1).
 */
class EcTest {

    @Test
    void ecAddShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcAdd(ops::add);
        // +21 ops / +21 bytes over the pre-P==-Q-fix shape: the second
        // OP_NUMEQUAL on y, the OP_BOOLAND that ANDs it into `cond`, the
        // OP_SUB/OP_NOT that build `notinf`, the two OP_MULs that mask rx/ry,
        // and the picks/rolls that feed them. All 1-byte ops, hence op count
        // and byte count move together.
        //
        // CL-BUG-096 then added a further +50 / +50: emitAffineInfinitySelect
        // replaces the four toTop/drop cleanups and the two `notinf` OP_MULs
        // with the pinf/qinf/usep/useq/user select. Again all 1-byte ops.
        assertEquals(8297, countOpTree(ops), "ecAdd op count drift");

        String hex = emitHex(ops);
        assertEquals(25634, hex.length() / 2, "ecAdd hex byte count drift");
    }

    @Test
    void ecMulShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcMul(ops::add);
        assertEquals(130526, countOpTree(ops), "ecMul op count drift");
        assertEquals(428754, emitHex(ops).length() / 2);
    }

    @Test
    void ecMulGenShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcMulGen(ops::add);
        assertEquals(130528, countOpTree(ops), "ecMulGen op count drift");
        assertEquals(428820, emitHex(ops).length() / 2);
    }

    @Test
    void ecNegateShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcNegate(ops::add);
        assertEquals(956, countOpTree(ops));
        assertEquals(1096, emitHex(ops).length() / 2);
    }

    @Test
    void ecOnCurveShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcOnCurve(ops::add);
        assertEquals(548, countOpTree(ops));
        assertEquals(816, emitHex(ops).length() / 2);
    }

    @Test
    void ecModReduceIsExactEightOps() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcModReduce(ops::add);
        assertEquals(8, countOpTree(ops));
        // OP_2DUP, OP_MOD, OP_ROT, OP_DROP, OP_OVER, OP_ADD, OP_SWAP, OP_MOD
        assertTrue(ops.get(0) instanceof OpcodeOp
            && "OP_2DUP".equals(((OpcodeOp) ops.get(0)).code()));
        assertTrue(ops.get(1) instanceof OpcodeOp
            && "OP_MOD".equals(((OpcodeOp) ops.get(1)).code()));
        assertTrue(ops.get(2) instanceof RotOp);
        assertTrue(ops.get(3) instanceof DropOp);
        assertTrue(ops.get(4) instanceof OverOp);
        assertTrue(ops.get(5) instanceof OpcodeOp
            && "OP_ADD".equals(((OpcodeOp) ops.get(5)).code()));
        assertTrue(ops.get(6) instanceof SwapOp);
        assertTrue(ops.get(7) instanceof OpcodeOp
            && "OP_MOD".equals(((OpcodeOp) ops.get(7)).code()));
    }

    @Test
    void ecEncodeCompressedShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcEncodeCompressed(ops::add);
        assertEquals(16, countOpTree(ops));
        assertEquals(21, emitHex(ops).length() / 2);
    }

    @Test
    void ecMakePointShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcMakePoint(ops::add);
        assertEquals(467, countOpTree(ops));
        assertEquals(471, emitHex(ops).length() / 2);
    }

    @Test
    void ecPointXShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcPointX(ops::add);
        assertEquals(236, countOpTree(ops));
        assertEquals(239, emitHex(ops).length() / 2);
    }

    @Test
    void ecPointYShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcPointY(ops::add);
        assertEquals(237, countOpTree(ops));
        assertEquals(240, emitHex(ops).length() / 2);
    }

    @Test
    void dispatchRecognisesAllBuiltins() {
        String[] names = {
            "ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecOnCurve",
            "ecModReduce", "ecEncodeCompressed", "ecMakePoint",
            "ecPointX", "ecPointY"
        };
        for (String n : names) {
            assertTrue(Ec.isEcBuiltin(n), n + " should be an EC builtin");
        }
        assertFalse(Ec.isEcBuiltin("ecUnknown"));
    }

    @Test
    void dispatchThrowsOnUnknown() {
        assertThrows(RuntimeException.class,
            () -> Ec.dispatch("ecBanana", op -> {}));
    }

    @Test
    void curveConstantsAreCorrect() {
        // p = 2^256 - 2^32 - 977
        BigInteger expectedP = BigInteger.TWO.pow(256)
            .subtract(BigInteger.TWO.pow(32))
            .subtract(BigInteger.valueOf(977));
        assertEquals(expectedP, Ec.EC_FIELD_P);

        // n is the secp256k1 group order
        BigInteger expectedN = new BigInteger(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
        assertEquals(expectedN, Ec.EC_CURVE_N);
    }

    // ---- helpers ----

    /**
     * Total number of {@link StackOp}s in {@code ops}, INCLUDING the bodies of
     * {@code if} ops.
     *
     * <p>A flat {@code ops.size()} cannot see inside a branch, so any emitter
     * whose work sits in an {@code if} body — the ladder emits 257 conditional
     * additions — reports a count that barely moves no matter what the branch
     * contains. Recursing is what makes the golden a gate.
     */
    private static int countOpTree(List<StackOp> ops) {
        int total = 0;
        for (StackOp op : ops) {
            total++;
            if (op instanceof IfOp ifOp) {
                if (ifOp.thenBranch() != null) total += countOpTree(ifOp.thenBranch());
                if (ifOp.elseBranch() != null) total += countOpTree(ifOp.elseBranch());
            }
        }
        return total;
    }

    private static String emitHex(List<StackOp> ops) {
        StackProgram prog = new StackProgram("Test",
            List.of(new StackMethod("run", ops, 0L)));
        return Emit.run(prog);
    }
}
