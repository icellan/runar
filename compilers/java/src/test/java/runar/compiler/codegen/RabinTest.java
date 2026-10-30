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
 * <p>The reference is the fixed 34-op sequence (post F-368) in
 * {@code packages/runar-compiler/src/passes/rabin-codegen.ts}:
 *
 * <pre>
 *   &lt;push 0x00&gt; OP_CAT OP_BIN2NUM                   // pubKey as unsigned (F-144)
 *   OP_SWAP
 *   &lt;push 0x00&gt; OP_CAT OP_BIN2NUM                   // padding as unsigned (F-144)
 *   OP_DUP OP_0 &lt;push 65536&gt; OP_WITHIN OP_VERIFY   // 0 &lt;= padding &lt; 65536 (BUG-010)
 *   OP_ROT
 *   &lt;push 0x00&gt; OP_CAT OP_BIN2NUM                   // sig as unsigned (F-144)
 *   OP_DUP OP_3 OP_PICK OP_LESSTHAN OP_VERIFY      // sig &lt; pubKey (F-368)
 *   OP_DUP OP_MUL OP_ADD OP_OVER OP_MOD
 *   OP_ROT OP_SHA256 &lt;push 0x00&gt; OP_CAT OP_BIN2NUM
 *   OP_ROT OP_MOD OP_NUMEQUAL                       // digest mod pubKey (F-047)
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
    void emitsExactly34Ops() {
        List<StackOp> ops = capture();
        assertEquals(34, ops.size(),
            "Rabin verifier must emit exactly 34 opcodes (cross-compiler reference; "
                + "10 original + 5 BUG-010 range-check ops + 4 BUG-011 "
                + "digest-encoding ops, less the OP_EQUAL that OP_NUMEQUAL replaced, "
                + "+ 2 F-047 digest-reduction ops + 9 F-144 operand-sign ops "
                + "+ 5 F-368 sig < pubKey ops)");
    }

    @Test
    void allOpsAreOpcodeOpsExceptPaddingLimitPush() {
        List<StackOp> ops = capture();
        for (int i = 0; i < ops.size(); i++) {
            StackOp op = ops.get(i);
            if (i == 0 || i == 4 || i == 9 || i == 13 || i == 17 || i == 28) {
                // 0/4/13 = F-144 operand sign bytes, 9 = BUG-010 padding limit,
                // 17 = F-368 pick depth, 28 = BUG-011 digest sign byte.
                assertTrue(op instanceof PushOp,
                    "Rabin op " + i + " must be a push; got "
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
        // Position 9 is the padding-limit push (65536); marked with null below
        // so the loop body verifies it separately, as is 17 (the F-368 pick
        // depth 3). 0, 4, 13 and 28 are 0x00 sign-byte pushes (F-144
        // operands, BUG-011 digest).
        List<String> expected = java.util.Arrays.asList(
            null, // F-144: pubKey sign byte (0x00)
            "OP_CAT",
            "OP_BIN2NUM",
            "OP_SWAP",
            null, // F-144: padding sign byte (0x00)
            "OP_CAT",
            "OP_BIN2NUM",
            "OP_DUP",
            "OP_0",
            null, // push 65536
            "OP_WITHIN",
            "OP_VERIFY",
            "OP_ROT",
            null, // F-144: sig sign byte (0x00)
            "OP_CAT",
            "OP_BIN2NUM",
            "OP_DUP", // F-368: sig < pubKey
            null, // push 3
            "OP_PICK",
            "OP_LESSTHAN",
            "OP_VERIFY",
            "OP_DUP",
            "OP_MUL",
            "OP_ADD",
            "OP_OVER", // F-047: keep pubKey for the digest reduction
            "OP_MOD",
            "OP_ROT",
            "OP_SHA256",
            null, // BUG-011 digest sign byte (0x00)
            "OP_CAT",
            "OP_BIN2NUM",
            "OP_ROT", // F-047
            "OP_MOD", // F-047: SHA256(msg) mod pubKey
            "OP_NUMEQUAL"
        );
        assertEquals(expected.size(), ops.size());
        for (int i = 0; i < expected.size(); i++) {
            String want = expected.get(i);
            if (want == null && i == 9) {
                PushOp p = (PushOp) ops.get(i);
                assertEquals(BigInteger.valueOf(Rabin.RABIN_PADDING_LIMIT),
                    p.value().raw(),
                    "Rabin op " + i + " must push the BUG-010 padding limit");
            } else if (want == null && i == 17) {
                PushOp p = (PushOp) ops.get(i);
                assertEquals(BigInteger.valueOf(3), p.value().raw(),
                    "Rabin op " + i + " must push the F-368 pick depth 3");
            } else if (want == null) {
                // F-144 operand sign bytes and the BUG-011 digest sign byte:
                // each makes the item below it read as a NON-NEGATIVE Script number.
                PushOp p = (PushOp) ops.get(i);
                assertEquals("00", p.value().raw(),
                    "Rabin op " + i + " must push a 0x00 sign byte");
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
        assertEquals(34, ops.size());
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
