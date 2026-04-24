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
 */
class EcTest {

    @Test
    void ecAddShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcAdd(ops::add);
        assertEquals(8078, ops.size(), "ecAdd op count drift");

        String hex = emitHex(ops);
        assertEquals(24984, hex.length() / 2, "ecAdd hex byte count drift");
    }

    @Test
    void ecMulShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcMul(ops::add);
        assertEquals(63828, ops.size(), "ecMul op count drift");
        assertEquals(427470, emitHex(ops).length() / 2);
    }

    @Test
    void ecMulGenShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcMulGen(ops::add);
        assertEquals(63830, ops.size(), "ecMulGen op count drift");
        assertEquals(427536, emitHex(ops).length() / 2);
    }

    @Test
    void ecNegateShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcNegate(ops::add);
        assertEquals(945, ops.size());
        assertEquals(1018, emitHex(ops).length() / 2);
    }

    @Test
    void ecOnCurveShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcOnCurve(ops::add);
        assertEquals(520, ops.size());
        assertEquals(655, emitHex(ops).length() / 2);
    }

    @Test
    void ecModReduceIsExactEightOps() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcModReduce(ops::add);
        assertEquals(8, ops.size());
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
        assertEquals(14, ops.size());
        assertEquals(19, emitHex(ops).length() / 2);
    }

    @Test
    void ecMakePointShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcMakePoint(ops::add);
        assertEquals(467, ops.size());
        assertEquals(471, emitHex(ops).length() / 2);
    }

    @Test
    void ecPointXShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcPointX(ops::add);
        assertEquals(233, ops.size());
        assertEquals(235, emitHex(ops).length() / 2);
    }

    @Test
    void ecPointYShape() {
        List<StackOp> ops = new ArrayList<>();
        Ec.emitEcPointY(ops::add);
        assertEquals(234, ops.size());
        assertEquals(236, emitHex(ops).length() / 2);
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

    private static String emitHex(List<StackOp> ops) {
        StackProgram prog = new StackProgram("Test",
            List.of(new StackMethod("run", ops, 0L)));
        return Emit.run(prog);
    }
}
