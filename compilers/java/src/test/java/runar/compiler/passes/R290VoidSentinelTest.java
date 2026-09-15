package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.ast.ContractNode;

/**
 * R-290 — {@code inlinePrivateMethodCall} used to emit a
 * {@code load_const "@void"} sentinel when the inlined body produced no
 * bindings.
 *
 * <p>No tier's stack lowering recognises {@code "@void"} (unlike
 * {@code "@this"}, which IS special-cased), so the sentinel survived pass 4
 * and died in the hex decoder: Go said {@code invalid byte: U+0040 '@'}, Rust
 * said {@code invalid hex string length: 5}. Neither names the method or the
 * problem, and both fire only because the string happens to be odd-length and
 * non-hex — an even-length sentinel would decode to zeros in Rust's
 * {@code from_str_radix(..).unwrap_or(0)} and reach the script.
 *
 * <p>In the Go / Rust / Python / TypeScript tiers it is REACHABLE: their
 * side-effect summary resolves a called name through a LAST-WINS map and
 * caches the result under that name, while {@code getPrivateMethod} returns the
 * FIRST match. Declare the public caller BEFORE two same-named privates and the
 * two disagree — the summary describes the output-emitting {@code helper}, so
 * inlining fires, while the lowerer inlines the EMPTY one. Measured on the Go
 * CLI pre-fix: {@code --emit-ir} exit 0 with {@code @void} in the IR.
 *
 * <p>This tier is NOT reachable that way: {@code shouldInlinePrivate} asks
 * {@code getPrivateMethod} — the same first-match lookup the inliner uses — so
 * the two cannot disagree. The refusal still ships here, because the sentinel
 * must not exist in any tier and because the tiers' inline-decision paths have
 * drifted before. The test below therefore pins the INVARIANT rather than the
 * refusal: whatever this tier does with that contract, no {@code @void} may
 * survive into the ANF. If a future change routes this tier's inline decision
 * through a summary map, the contract starts refusing and the first branch
 * takes over.
 */
class R290VoidSentinelTest {

    private static final String EMPTY_INLINED_BODY = """
        class R290Void extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }

          public go(x: bigint) {
            this.count = x;
            this.helper();
          }

          private helper(): void {
          }

          private helper(): void {
            this.addOutput(1000n, this.count);
          }
        }
        """;

    /**
     * Control: the ordinary shape — one private helper that really does emit
     * an output. The inlining path must still work; a refusal that simply
     * rejected every inlined private would pass the test above.
     */
    private static final String CONTROL_EMITTING_HELPER = """
        class R290Control extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }

          public go(x: bigint) {
            this.count = x;
            this.helper();
          }

          private helper(): void {
            this.addOutput(1000n, this.count);
          }
        }
        """;

    private static boolean carriesVoidSentinel(List<AnfBinding> body) {
        for (AnfBinding b : body) {
            AnfValue v = b.value();
            if (v instanceof LoadConst lc && "@void".equals(lc.value().raw())) return true;
            if (v instanceof If i
                && (carriesVoidSentinel(i.thenBranch()) || carriesVoidSentinel(i.elseBranch()))) {
                return true;
            }
            if (v instanceof Loop l && carriesVoidSentinel(l.body())) return true;
        }
        return false;
    }

    private static boolean carriesVoidSentinel(AnfProgram program) {
        for (AnfMethod m : program.methods()) {
            if (carriesVoidSentinel(m.body())) return true;
        }
        return false;
    }

    @Test
    void emptyInlinedBodyNeverYieldsASentinel() throws Exception {
        ContractNode contract = ParserDispatch.parse(EMPTY_INLINED_BODY, "R290Void.runar.ts");
        AnfProgram program;
        try {
            program = AnfLower.run(contract);
        } catch (IllegalStateException e) {
            assertTrue(
                e.getMessage().contains("was inlined but produced no bindings"),
                "refused, but not with the R-290 diagnostic: " + e.getMessage());
            return;
        }
        assertFalse(
            carriesVoidSentinel(program),
            "the empty inlined body produced the @void sentinel instead of a refusal");
    }

    @Test
    void ordinaryInlinedHelperCarriesNoSentinel() throws Exception {
        ContractNode contract =
            ParserDispatch.parse(CONTROL_EMITTING_HELPER, "R290Control.runar.ts");
        AnfProgram program = AnfLower.run(contract);
        assertFalse(carriesVoidSentinel(program), "the @void sentinel is still emitted somewhere");
    }

    @Test
    void emittingHelperStillInlines() throws Exception {
        ContractNode contract =
            ParserDispatch.parse(CONTROL_EMITTING_HELPER, "R290Control.runar.ts");
        assertDoesNotThrow(() -> AnfLower.run(contract));
    }
}
