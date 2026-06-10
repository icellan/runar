package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.StackOp;

/**
 * Direct unit tests for the Rabin signature verifier codegen.
 *
 * <p>The reference is the fixed 15-opcode sequence (post BUG-010) in
 * {@code packages/runar-compiler/src/passes/rabin-codegen.ts}:
 *
 * <pre>
 *   OP_SWAP
 *   OP_DUP OP_0 &lt;push 65536&gt; OP_WITHIN OP_VERIFY   // 0 &lt;= padding &lt; 65536
 *   OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
 * </pre>
 *
 * <p>The Java emitter must produce that exact sequence to remain byte-identical
 * with the other 6 compilers. The conformance runner exercises this via
 * end-to-end fixtures, but a direct unit test catches a regression instantly.
 * See {@code _review/BUG-010-rfc.md}.
 */
class RabinTest {

    private static List<StackOp> capture() {
        List<StackOp> ops = new ArrayList<>();
        Rabin.emitVerifyRabinSig(ops::add);
        return ops;
    }

    @Test
    void emitsExactly15Ops() {
        List<StackOp> ops = capture();
        assertEquals(15, ops.size(),
            "Rabin verifier must emit exactly 15 opcodes (cross-compiler reference; "
                + "10 original + 5 BUG-010 range-check ops)");
    }

    @Test
    void allOpsAreOpcodeOpsExceptPaddingLimitPush() {
        List<StackOp> ops = capture();
        for (int i = 0; i < ops.size(); i++) {
            StackOp op = ops.get(i);
            if (i == 3) {
                assertTrue(op instanceof PushOp,
                    "Rabin op 3 must be the BUG-010 padding-limit push; got "
                        + op.getClass().getSimpleName());
            } else {
                assertTrue(op instanceof OpcodeOp,
                    "Rabin op " + i + " must be OpcodeOp; got "
                        + op.getClass().getSimpleName());
            }
        }
    }

    @Test
    void exactOpcodeSequenceMatchesReference() {
        List<StackOp> ops = capture();
        // Position 3 is the padding-limit push (65536); marked with null below
        // so the loop body verifies it separately.
        List<String> expected = java.util.Arrays.asList(
            "OP_SWAP",
            "OP_DUP",
            "OP_0",
            null, // push 65536
            "OP_WITHIN",
            "OP_VERIFY",
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
            String want = expected.get(i);
            if (want == null) {
                PushOp p = (PushOp) ops.get(i);
                assertEquals(BigInteger.valueOf(Rabin.RABIN_PADDING_LIMIT),
                    p.value().raw(),
                    "Rabin op " + i + " must push the BUG-010 padding limit");
            } else {
                OpcodeOp actual = (OpcodeOp) ops.get(i);
                assertEquals(want, actual.code(),
                    "Opcode at offset " + i + " diverges from reference");
            }
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
        assertEquals(15, ops.size());
    }

    @Test
    void dispatchRejectsUnknownName() {
        assertThrows(RuntimeException.class, () -> Rabin.dispatch("verifyFoo", op -> {}));
    }

    @Test
    void emitterContainsBug010PaddingLimitPush() {
        // Defensive: an emitter that drops the BUG-010 push (e.g. via a botched
        // refactor) would re-introduce the forgery exploit. This is a targeted
        // regression test for that scenario.
        List<StackOp> ops = capture();
        boolean foundPush = false;
        for (StackOp op : ops) {
            if (op instanceof PushOp p
                && p.value().raw() instanceof BigInteger bi
                && bi.equals(BigInteger.valueOf(Rabin.RABIN_PADDING_LIMIT))) {
                foundPush = true;
                break;
            }
        }
        assertNotNull(ops);
        assertTrue(foundPush,
            "Rabin emitter MUST push the BUG-010 padding limit (65536); "
                + "without it, an attacker can forge signatures by choosing arbitrary padding.");
    }
}
