package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.stack.StackProgram;

/**
 * N-262 — {@code lowerIf} phase 3 must refuse to pad a NON-EMPTY arm.
 *
 * <p>Phase 3 balances the two arms of an OP_IF by pushing an OP_0 on the
 * shallower one. Padding an arm with NO bindings is the legitimate #99
 * fallback; padding an arm that DID compute something writes a placeholder the
 * post-ENDIF code reads as a value (the OP_0-in-the-taken-arm shape). Go has
 * refused it since R-161; the other six tiers padded silently.
 *
 * <p>The program is hand-built {@code --ir} input: an arm ending in a
 * non-terminal {@code assert} is one slot shallower than a sibling arm that
 * leaves a value.
 *
 * <p>Proves: both padding directions fail with the shared internal-codegen
 * sentence (same words as compilers/go/codegen/stack.go), and padding an EMPTY
 * arm still compiles. Does not prove that no source program reaches the guard
 * (golden conformance covers the corpus).
 */
class N262NonEmptyArmPaddingTest {

    private static final String VALUE_ARM =
        "[{\"name\":\"a\",\"value\":{\"kind\":\"load_const\",\"value\":1}}]";
    private static final String ASSERT_ARM =
        "[{\"name\":\"k\",\"value\":{\"kind\":\"load_const\",\"value\":1}},"
            + "{\"name\":\"k2\",\"value\":{\"kind\":\"assert\",\"value\":\"k\"}}]";

    private static String ir(String thenArm, String elseArm) {
        return """
            {"contractName":"P","properties":[],"methods":[{"name":"m","isPublic":true,
              "params":[{"name":"x","type":"bigint"}],"body":[
              {"name":"t0","value":{"kind":"load_param","name":"x"}},
              {"name":"t1","value":{"kind":"load_const","value":0}},
              {"name":"t2","value":{"kind":"bin_op","op":">","left":"t0","right":"t1"}},
              {"name":"t3","value":{"kind":"if","cond":"t2","then":%s,"else":%s}},
              {"name":"t4","value":{"kind":"assert","value":"t3"}}]}]}
            """.formatted(thenArm, elseArm);
    }

    private static String hexOf(String json) {
        AnfProgram anf = AnfLoader.parse(json);
        StackProgram stack = StackLower.run(anf);
        return Emit.run(Peephole.run(stack));
    }

    @Test
    void aNonEmptyElseArmIsNeverPadded() {
        RuntimeException e = assertThrows(RuntimeException.class, () -> hexOf(ir(VALUE_ARM, ASSERT_ARM)));
        assertTrue(
            e.getMessage().contains(
                "internal codegen error: conditional needs 1 placeholder push(es) to balance a NON-EMPTY "
                    + "else arm (then depth 1 != else depth 0)"),
            e.getMessage());
        assertTrue(e.getMessage().contains("binding=\"t3\""), e.getMessage());
    }

    @Test
    void aNonEmptyThenArmIsNeverPadded() {
        RuntimeException e = assertThrows(RuntimeException.class, () -> hexOf(ir(ASSERT_ARM, VALUE_ARM)));
        assertTrue(
            e.getMessage().contains(
                "internal codegen error: conditional needs 1 placeholder push(es) to balance a NON-EMPTY "
                    + "then arm (else depth 1 != then depth 0)"),
            e.getMessage());
        assertTrue(e.getMessage().contains("binding=\"t3\""), e.getMessage());
    }

    @Test
    void anEmptyElseArmIsStillPadded() {
        assertFalse(hexOf(ir(VALUE_ARM, "[]")).isEmpty());
    }
}
