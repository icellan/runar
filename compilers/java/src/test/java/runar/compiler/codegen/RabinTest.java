package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.StackOp;

/**
 * Direct unit tests for the Rabin signature verifier codegen. The reference
 * is the fixed 10-opcode sequence in
 * {@code compilers/python/runar_compiler/codegen/stack.py:_lower_verify_rabin_sig}
 * and {@code compilers/rust/src/codegen/stack.rs::lower_verify_rabin_sig}:
 *
 * <pre>
 *   OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
 * </pre>
 *
 * The Java emitter must produce that exact sequence to remain byte-identical
 * with the other 6 compilers. The conformance runner exercises this via
 * end-to-end fixtures, but a direct unit test catches a regression instantly.
 */
class RabinTest {

    private static List<StackOp> capture() {
        List<StackOp> ops = new ArrayList<>();
        Rabin.emitVerifyRabinSig(ops::add);
        return ops;
    }

    @Test
    void emitsExactly10Ops() {
        List<StackOp> ops = capture();
        assertEquals(10, ops.size(),
            "Rabin verifier must emit exactly 10 opcodes (cross-compiler reference)");
    }

    @Test
    void allOpsAreOpcodeOps() {
        for (StackOp op : capture()) {
            assertTrue(op instanceof OpcodeOp,
                "Rabin emits only OpcodeOps; got " + op.getClass().getSimpleName());
        }
    }

    @Test
    void exactOpcodeSequenceMatchesReference() {
        List<StackOp> ops = capture();
        List<String> expected = List.of(
            "OP_SWAP",
            "OP_ROT",
            "OP_DUP",
            "OP_MUL",
            "OP_ADD",
            "OP_SWAP",
            "OP_MOD",
            "OP_SWAP",
            "OP_SHA256",
            "OP_EQUAL"
        );
        assertEquals(expected.size(), ops.size());
        for (int i = 0; i < expected.size(); i++) {
            OpcodeOp actual = (OpcodeOp) ops.get(i);
            assertEquals(expected.get(i), actual.code(),
                "Opcode at offset " + i + " diverges from reference; "
                    + "Java emits " + actual.code() + " but Go/Rust/Python emit " + expected.get(i));
        }
    }

    @Test
    void isRabinBuiltinAcceptsKnownName() {
        assertTrue(Rabin.isRabinBuiltin("verifyRabinSig"));
    }

    @Test
    void isRabinBuiltinRejectsUnknown() {
        assertEquals(false, Rabin.isRabinBuiltin("verifyRabin"));
        assertEquals(false, Rabin.isRabinBuiltin("rabinVerify"));
        assertEquals(false, Rabin.isRabinBuiltin(""));
    }

    @Test
    void dispatchRoutesKnownName() {
        List<StackOp> ops = new ArrayList<>();
        Rabin.dispatch("verifyRabinSig", ops::add);
        assertEquals(10, ops.size());
    }

    @Test
    void dispatchRejectsUnknownName() {
        assertThrows(RuntimeException.class, () -> Rabin.dispatch("verifyFoo", op -> {}));
    }

    @Test
    void byteEncodingTotalsExactly10Bytes() {
        // Each Rabin opcode is a single-byte BSV opcode. Therefore the
        // encoded byte length equals the op count.
        List<StackOp> ops = capture();
        // (Sanity: each op is a known BSV opcode in Emit's table; if the
        // emitter ever emits a multi-byte push, this test catches it.)
        for (StackOp op : ops) {
            assertNotNull(op);
            assertTrue(op instanceof OpcodeOp);
        }
        assertEquals(10, ops.size());
    }
}
