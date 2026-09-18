package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * R-189 — a private method may shadow a builtin, and nothing upstream of ANF
 * lowering notices when the two disagree about arity.
 *
 * <p>Typecheck resolves a BARE-IDENTIFIER call against the builtin table
 * BEFORE it looks at the contract's own methods; ANF lowering resolves the
 * same call against private methods FIRST. So {@code min(x, y)} against
 * {@code private min(a, b, c)} type-checks as the two-argument BUILTIN
 * {@code min} and then lowers as the three-parameter METHOD {@code min}. No
 * validator forbids the shadowing.
 *
 * <p>The zip that bound params to args stopped at the shorter list. When the
 * surplus parameter was never read the contract compiled CLEAN — an arity
 * mismatch silently accepted. When it was read, the defect surfaced two passes
 * later as "method parameter 'c' is not on the stack", a stack-lowering
 * message about a pass the author never wrote in.
 */
class R189PrivateCallArityTest {

    /** The silent case: {@code c} is never read, so nothing downstream noticed. */
    private static final String SURPLUS_PARAM_UNREAD = """
        class R189Unread extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }

          private min(a: bigint, b: bigint, c: bigint): bigint {
            this.count = a + b;
            this.addOutput(1000n, this.count);
            return a;
          }

          public go(x: bigint, y: bigint) {
            min(x, y);
          }
        }
        """;

    /** Too many arguments: {@code y} was evaluated and then dropped on the floor. */
    private static final String TOO_MANY_ARGS = """
        class R189Extra extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }

          private min(a: bigint): bigint {
            this.count = a;
            this.addOutput(1000n, this.count);
            return a;
          }

          public go(x: bigint, y: bigint) {
            min(x, y);
          }
        }
        """;

    /**
     * Control 1: the SAME builtin-shadowing private, called at its real arity
     * through {@code this.} — the bare form cannot reach pass 4 at arity 3,
     * because pass 3 checks it against the two-argument BUILTIN {@code min}.
     */
    private static final String CONTROL_SHADOWING_AT_REAL_ARITY = """
        class R189ControlShadow extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }

          private min(a: bigint, b: bigint, c: bigint): bigint {
            this.count = a + b + c;
            this.addOutput(1000n, this.count);
            return a;
          }

          public go(x: bigint, y: bigint, z: bigint) {
            this.min(x, y, z);
          }
        }
        """;

    /**
     * Control 2: an ordinary private helper, bare-identifier call at matching
     * arity — the Move / Go-DSL lowering path this refusal sits directly on.
     * Without the controls, a refusal that simply rejected every private call
     * would pass both refusal tests above.
     */
    private static final String CONTROL_PLAIN_PRIVATE = """
        class R189ControlPlain extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }

          private tally(a: bigint, b: bigint): bigint {
            this.count = a + b;
            this.addOutput(1000n, this.count);
            return a;
          }

          public go(x: bigint, y: bigint) {
            tally(x, y);
          }
        }
        """;

    private static ContractNode parse(String source) throws Exception {
        return ParserDispatch.parse(source, "R189.runar.ts");
    }

    @Test
    void surplusParameterIsRefusedNotSilentlyDropped() throws Exception {
        ContractNode contract = parse(SURPLUS_PARAM_UNREAD);
        IllegalStateException e =
            assertThrows(IllegalStateException.class, () -> AnfLower.run(contract),
                "arity mismatch was accepted: ANF lowering produced a program");
        assertTrue(
            e.getMessage().contains("private method 'min' expects 3 argument(s), got 2."),
            "refusal does not name the mismatch: " + e.getMessage());
    }

    @Test
    void surplusArgumentIsRefusedNotSilentlyDropped() throws Exception {
        ContractNode contract = parse(TOO_MANY_ARGS);
        IllegalStateException e =
            assertThrows(IllegalStateException.class, () -> AnfLower.run(contract),
                "arity mismatch was accepted: ANF lowering produced a program");
        assertTrue(
            e.getMessage().contains("private method 'min' expects 1 argument(s), got 2."),
            "refusal does not name the mismatch: " + e.getMessage());
    }

    @Test
    void shadowingPrivateAtRealArityStillLowers() throws Exception {
        ContractNode contract = parse(CONTROL_SHADOWING_AT_REAL_ARITY);
        assertDoesNotThrow(() -> AnfLower.run(contract));
    }

    @Test
    void plainPrivateHelperStillLowers() throws Exception {
        ContractNode contract = parse(CONTROL_PLAIN_PRIVATE);
        assertDoesNotThrow(() -> AnfLower.run(contract));
    }
}
