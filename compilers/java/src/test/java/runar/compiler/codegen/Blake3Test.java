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
 * Byte-identical parity tests for {@link Blake3} against the Go and Python
 * reference codegen.
 *
 * <p>Goldens were captured by running the Go reference
 * ({@code compilers/go/codegen/blake3.go}) through {@code EmitBlake3Compress}
 * / {@code EmitBlake3Hash} on the same commit as this port. Any divergence
 * means the Java emitter has drifted and the compiler will produce
 * non-conforming hex.
 */
class Blake3Test {

    // ------------------------------------------------------------------
    // Op-count goldens (from compilers/go/codegen/blake3.go)
    // ------------------------------------------------------------------

    @Test
    void compressOpCount() {
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Compress(ops::add);
        assertEquals(10819, ops.size(), "blake3Compress op count drift");
    }

    @Test
    void hashOpCount() {
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Hash(ops::add);
        assertEquals(10829, ops.size(), "blake3Hash op count drift");
    }

    // ------------------------------------------------------------------
    // Op-shape goldens
    // ------------------------------------------------------------------

    @Test
    void compressOpcodesStartCorrectly() {
        // Compression starts by splitting the 64-byte block into 16x4-byte
        // BE words. First 30 ops alternate (push 4, OP_SPLIT) x15.
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Compress(ops::add);

        for (int i = 0; i < 30; i += 2) {
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
    void hashOpcodesStartCorrectly() {
        // Hash starts with: OP_SIZE, push 64, SWAP, OP_SUB, push 0, SWAP,
        // OP_NUM2BIN, OP_CAT, push 32-byte IV, SWAP, then the compress ops.
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Hash(ops::add);

        assertTrue(ops.get(0) instanceof OpcodeOp
            && "OP_SIZE".equals(((OpcodeOp) ops.get(0)).code()),
            "op[0] must be OP_SIZE");
        assertTrue(ops.get(1) instanceof PushOp);
        assertEquals(BigInteger.valueOf(64),
            ((BigIntPushValue) ((PushOp) ops.get(1)).value()).value());
        assertTrue(ops.get(2) instanceof SwapOp, "op[2] must be SWAP");
        assertTrue(ops.get(3) instanceof OpcodeOp
            && "OP_SUB".equals(((OpcodeOp) ops.get(3)).code()),
            "op[3] must be OP_SUB");
        assertTrue(ops.get(4) instanceof PushOp);
        assertEquals(BigInteger.ZERO,
            ((BigIntPushValue) ((PushOp) ops.get(4)).value()).value());
        assertTrue(ops.get(5) instanceof SwapOp);
        assertTrue(ops.get(6) instanceof OpcodeOp
            && "OP_NUM2BIN".equals(((OpcodeOp) ops.get(6)).code()));
        assertTrue(ops.get(7) instanceof OpcodeOp
            && "OP_CAT".equals(((OpcodeOp) ops.get(7)).code()));

        // op[8] = push 32-byte BE IV (big-endian concatenation of the 8 IV words)
        assertTrue(ops.get(8) instanceof PushOp);
        PushValue iv = ((PushOp) ops.get(8)).value();
        assertTrue(iv instanceof ByteStringPushValue, "op[8] must be byte push");
        // 32-byte IV: 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
        assertEquals(
            "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19",
            ((ByteStringPushValue) iv).hex());

        assertTrue(ops.get(9) instanceof SwapOp);
    }

    // ------------------------------------------------------------------
    // Hex parity goldens (vs Go reference codegen.EmitMethod output)
    // ------------------------------------------------------------------

    @Test
    void compressEmitsToGoldenHex() {
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Compress(ops::add);

        StackProgram prog = new StackProgram(
            "Test",
            List.of(new StackMethod("run", ops, 0L))
        );
        String hex = Emit.run(prog);
        assertFalse(hex.isEmpty(), "hex must not be empty");

        // From Go: compress hex byte length = 11632.
        assertEquals(11632, hex.length() / 2, "compress hex byte count drift");

        // From Go: first 32 bytes of compress hex.
        assertEquals(
            "547f547f547f547f547f547f547f547f547f547f547f547f547f547f547f517f",
            hex.substring(0, 64));
    }

    @Test
    void hashEmitsToGoldenHex() {
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Hash(ops::add);

        StackProgram prog = new StackProgram(
            "Test",
            List.of(new StackMethod("run", ops, 0L))
        );
        String hex = Emit.run(prog);
        assertFalse(hex.isEmpty(), "hex must not be empty");

        // From Go: hash hex byte length = 11675.
        assertEquals(11675, hex.length() / 2, "hash hex byte count drift");

        // From Go: first 32 bytes of hash hex.
        // 82 = OP_SIZE, 0140 = push 1 byte 0x40 (=64), 7c = SWAP, 94 = OP_SUB,
        // 00 = push 0, 7c = SWAP, 80 = OP_NUM2BIN, 7e = OP_CAT,
        // 20 = push 32 bytes (the IV), then 6a09e667...5be0cd19.
        assertEquals(
            "8201407c94007c807e206a09e667bb67ae853c6ef372a54ff53a510e527f9b05",
            hex.substring(0, 64));
    }

    // ------------------------------------------------------------------
    // Determinism
    // ------------------------------------------------------------------

    @Test
    void emitterIsDeterministic() {
        List<StackOp> a = new ArrayList<>();
        List<StackOp> b = new ArrayList<>();
        Blake3.emitBlake3Compress(a::add);
        Blake3.emitBlake3Compress(b::add);
        assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            assertEquals(opRepr(a.get(i)), opRepr(b.get(i)), "op " + i + " diverges");
        }

        a.clear(); b.clear();
        Blake3.emitBlake3Hash(a::add);
        Blake3.emitBlake3Hash(b::add);
        assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            assertEquals(opRepr(a.get(i)), opRepr(b.get(i)), "op " + i + " diverges");
        }
    }

    // ------------------------------------------------------------------
    // Dispatch
    // ------------------------------------------------------------------

    @Test
    void dispatchKnowsBlake3Names() {
        assertTrue(Blake3.isBlake3Builtin("blake3Compress"));
        assertTrue(Blake3.isBlake3Builtin("blake3Hash"));
        assertFalse(Blake3.isBlake3Builtin("sha256Compress"));
        assertFalse(Blake3.isBlake3Builtin("ecAdd"));
        assertFalse(Blake3.isBlake3Builtin("nonexistent"));
    }

    @Test
    void dispatchEmitsCorrectOps() {
        List<StackOp> direct = new ArrayList<>();
        Blake3.emitBlake3Compress(direct::add);

        List<StackOp> dispatched = new ArrayList<>();
        Blake3.dispatch("blake3Compress", dispatched::add);

        assertEquals(direct.size(), dispatched.size());
        for (int i = 0; i < direct.size(); i++) {
            assertEquals(opRepr(direct.get(i)), opRepr(dispatched.get(i)),
                "dispatch differs at op " + i);
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
