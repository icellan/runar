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
        assertEquals(10379, ops.size(), "blake3Compress op count drift");
    }

    @Test
    void hashOpCount() {
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Hash(ops::add);
        assertEquals(10387, ops.size(), "blake3Hash op count drift");
    }

    // ------------------------------------------------------------------
    // Op-shape goldens
    // ------------------------------------------------------------------

    @Test
    void compressOpcodesStartCorrectly() {
        // F-114: the block size guard (OP_SIZE, push 64, OP_EQUALVERIFY)
        // comes first. Then compression splits the 64-byte block into
        // 16x4-byte LE words: the next 30 ops alternate (push 4, OP_SPLIT) x15.
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Compress(ops::add);

        assertTrue(ops.get(0) instanceof OpcodeOp
            && "OP_SIZE".equals(((OpcodeOp) ops.get(0)).code()), "op[0] must be OP_SIZE");
        assertEquals(BigInteger.valueOf(64),
            ((BigIntPushValue) ((PushOp) ops.get(1)).value()).value(), "op[1] must push 64");
        assertTrue(ops.get(2) instanceof OpcodeOp
            && "OP_EQUALVERIFY".equals(((OpcodeOp) ops.get(2)).code()), "op[2] must be OP_EQUALVERIFY");

        for (int i = 3; i < 33; i += 2) {
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
        // Hash starts by capturing block_len = message length as a 4-byte LE
        // value on the alt stack: OP_SIZE, OP_DUP, push 4, OP_NUM2BIN,
        // OP_TOALTSTACK. Then it zero-pads the message to 64 bytes:
        // push 64, SWAP, OP_SUB, push 0, SWAP, OP_NUM2BIN, OP_CAT. Then it
        // pushes the 32-byte LE IV chaining value and SWAPs it below the
        // padded message, followed by the compress ops.
        List<StackOp> ops = new ArrayList<>();
        Blake3.emitBlake3Hash(ops::add);

        assertTrue(ops.get(0) instanceof OpcodeOp
            && "OP_SIZE".equals(((OpcodeOp) ops.get(0)).code()),
            "op[0] must be OP_SIZE");
        assertTrue(ops.get(1) instanceof OpcodeOp
            && "OP_DUP".equals(((OpcodeOp) ops.get(1)).code()),
            "op[1] must be OP_DUP");
        assertTrue(ops.get(2) instanceof PushOp);
        assertEquals(BigInteger.valueOf(4),
            ((BigIntPushValue) ((PushOp) ops.get(2)).value()).value());
        assertTrue(ops.get(3) instanceof OpcodeOp
            && "OP_NUM2BIN".equals(((OpcodeOp) ops.get(3)).code()),
            "op[3] must be OP_NUM2BIN");
        assertTrue(ops.get(4) instanceof OpcodeOp
            && "OP_TOALTSTACK".equals(((OpcodeOp) ops.get(4)).code()),
            "op[4] must be OP_TOALTSTACK");
        assertTrue(ops.get(5) instanceof PushOp);
        assertEquals(BigInteger.valueOf(64),
            ((BigIntPushValue) ((PushOp) ops.get(5)).value()).value());
        assertTrue(ops.get(6) instanceof SwapOp, "op[6] must be SWAP");
        assertTrue(ops.get(7) instanceof OpcodeOp
            && "OP_SUB".equals(((OpcodeOp) ops.get(7)).code()),
            "op[7] must be OP_SUB");
        assertTrue(ops.get(8) instanceof PushOp);
        assertEquals(BigInteger.ZERO,
            ((BigIntPushValue) ((PushOp) ops.get(8)).value()).value());
        assertTrue(ops.get(9) instanceof SwapOp);
        assertTrue(ops.get(10) instanceof OpcodeOp
            && "OP_NUM2BIN".equals(((OpcodeOp) ops.get(10)).code()));
        assertTrue(ops.get(11) instanceof OpcodeOp
            && "OP_CAT".equals(((OpcodeOp) ops.get(11)).code()));

        // op[12] = push 32-byte LE IV (little-endian concatenation of the 8 IV words)
        assertTrue(ops.get(12) instanceof PushOp);
        PushValue iv = ((PushOp) ops.get(12)).value();
        assertTrue(iv instanceof ByteStringPushValue, "op[12] must be byte push");
        // 32-byte LE IV: each of the 8 IV words 6a09e667 bb67ae85 3c6ef372
        // a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19 encoded little-endian.
        assertEquals(
            "67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b",
            ((ByteStringPushValue) iv).hex());

        assertTrue(ops.get(13) instanceof SwapOp);
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

        // LE port + F-114 operand guards (+8 bytes): compress hex byte length = 11194.
        assertEquals(11194, hex.length() / 2, "compress hex byte count drift");

        // First 32 bytes of compress hex: 82 0140 88 = OP_SIZE <64>
        // OP_EQUALVERIFY (F-114 block guard), then the 4-byte word splits.
        assertEquals(
            "82014088547f547f547f547f547f547f547f547f547f547f547f547f547f547f",
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

        // LE port: hash hex byte length = 11229.
        assertEquals(11229, hex.length() / 2, "hash hex byte count drift");

        // LE port: first 32 bytes of hash hex.
        // 82 = OP_SIZE, 76 = OP_DUP, 54 = OP_4 (push 4), 80 = OP_NUM2BIN,
        // 6b = OP_TOALTSTACK, 0140 = push 1 byte 0x40 (=64), 7c = SWAP,
        // 94 = OP_SUB, 00 = push 0, 7c = SWAP, 80 = OP_NUM2BIN, 7e = OP_CAT,
        // 20 = push 32 bytes (the LE IV), then 67e6096a...19cde05b.
        assertEquals(
            "827654806b01407c94007c807e2067e6096a85ae67bb72f36e3c3af54fa57f52",
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
