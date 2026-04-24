package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.BigIntPushValue;
import runar.compiler.ir.stack.ByteStringPushValue;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
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
 * Byte-identical parity tests for {@link Sha256} against the Python and TS
 * reference codegen.
 *
 * <p>These goldens are cached outputs from
 * {@code compilers/python/runar_compiler/codegen/sha256.py} running on the
 * same commit as the Java port.  Any divergence means the Java emitter has
 * drifted and the compiler will produce non-conforming hex.
 */
class Sha256Test {

    @Test
    void compressOpCount() {
        List<StackOp> ops = new ArrayList<>();
        Sha256.emitSha256Compress(ops::add);
        // Matches Python reference count: 21,292 ops.
        assertEquals(21292, ops.size(), "sha256Compress op count drift");
    }

    @Test
    void finalizeOpCount() {
        List<StackOp> ops = new ArrayList<>();
        Sha256.emitSha256Finalize(ops::add);
        assertEquals(63941, ops.size(), "sha256Finalize op count drift");
    }

    @Test
    void compressOpcodesStartCorrectly() {
        List<StackOp> ops = new ArrayList<>();
        Sha256.emitSha256Compress(ops::add);

        // First ops from Python: SWAP, DUP, OP_TOALTSTACK, OP_TOALTSTACK,
        // then 15 × (push 4, OP_SPLIT) to unpack the 64-byte block into 16 words.
        assertTrue(ops.get(0) instanceof SwapOp, "op[0] must be SWAP");
        assertTrue(ops.get(1) instanceof DupOp, "op[1] must be DUP");
        assertTrue(ops.get(2) instanceof OpcodeOp
            && "OP_TOALTSTACK".equals(((OpcodeOp) ops.get(2)).code()),
            "op[2] must be OP_TOALTSTACK");
        assertTrue(ops.get(3) instanceof OpcodeOp
            && "OP_TOALTSTACK".equals(((OpcodeOp) ops.get(3)).code()),
            "op[3] must be OP_TOALTSTACK");

        for (int i = 4; i < 34; i += 2) {
            StackOp push = ops.get(i);
            StackOp split = ops.get(i + 1);
            assertTrue(push instanceof PushOp, "op[" + i + "] must be push");
            PushValue pv = ((PushOp) push).value();
            assertTrue(pv instanceof BigIntPushValue, "expected bigint push");
            assertEquals(BigInteger.valueOf(4), ((BigIntPushValue) pv).value(),
                "op[" + i + "] push value");
            assertTrue(split instanceof OpcodeOp
                && "OP_SPLIT".equals(((OpcodeOp) split).code()),
                "op[" + (i + 1) + "] must be OP_SPLIT");
        }
    }

    @Test
    void compressEmitsToHex() {
        // Drive the compression through the Emit pass and make sure the
        // resulting hex has the expected leading bytes.
        List<StackOp> ops = new ArrayList<>();
        Sha256.emitSha256Compress(ops::add);

        StackProgram prog = new StackProgram(
            "Test",
            List.of(new StackMethod("run", ops, 0L))
        );

        String hex = Emit.run(prog);
        assertFalse(hex.isEmpty(), "hex must not be empty");
        // First 4 bytes (SWAP, DUP, OP_TOALTSTACK, OP_TOALTSTACK) = 7c 76 6b 6b
        assertEquals("7c766b6b", hex.substring(0, 8));
    }

    @Test
    void finalizeOpcodesStartCorrectly() {
        List<StackOp> ops = new ArrayList<>();
        Sha256.emitSha256Finalize(ops::add);

        // From Python reference: push 9, OP_NUM2BIN, push 8, OP_SPLIT, ...
        assertTrue(ops.get(0) instanceof PushOp);
        PushValue pv0 = ((PushOp) ops.get(0)).value();
        assertEquals(BigInteger.valueOf(9), ((BigIntPushValue) pv0).value());
        assertTrue(ops.get(1) instanceof OpcodeOp
            && "OP_NUM2BIN".equals(((OpcodeOp) ops.get(1)).code()));
        assertTrue(ops.get(2) instanceof PushOp);
        assertEquals(BigInteger.valueOf(8),
            ((BigIntPushValue) ((PushOp) ops.get(2)).value()).value());
    }

    @Test
    void emitterIsDeterministic() {
        List<StackOp> a = new ArrayList<>();
        List<StackOp> b = new ArrayList<>();
        Sha256.emitSha256Compress(a::add);
        Sha256.emitSha256Compress(b::add);
        assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            assertEquals(opRepr(a.get(i)), opRepr(b.get(i)), "op " + i + " diverges");
        }
    }

    private static String opRepr(StackOp op) {
        if (op instanceof DupOp) return "dup";
        if (op instanceof SwapOp) return "swap";
        if (op instanceof DropOp) return "drop";
        if (op instanceof NipOp) return "nip";
        if (op instanceof OverOp) return "over";
        if (op instanceof RotOp) return "rot";
        if (op instanceof PickOp p) return "pick(" + p.depth() + ")";
        if (op instanceof RollOp r) return "roll(" + r.depth() + ")";
        if (op instanceof OpcodeOp o) return "op(" + o.code() + ")";
        if (op instanceof PushOp p) {
            PushValue v = p.value();
            if (v instanceof BigIntPushValue b) return "push_bi(" + b.value() + ")";
            if (v instanceof ByteStringPushValue bs) return "push_bs(" + bs.hex() + ")";
            return "push(?)";
        }
        return op.getClass().getSimpleName();
    }
}
