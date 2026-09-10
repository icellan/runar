package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.Statement;

/**
 * N-019 (port of R-018, Rust): {@code this.arr[i]++} must be recognised as a
 * state mutation.
 *
 * <p>Two blind spots, both keyed on the operand of an increment/decrement being
 * a bare {@code PropertyAccessExpr}:
 *
 * <ol>
 *   <li><b>Lowering</b> — {@code AnfLower} emits an {@code update_prop} for an
 *       increment ONLY when the operand is a {@code PropertyAccessExpr}. After
 *       {@link ExpandFixedArrays} has run, {@code this.board[i]} (runtime
 *       index) is a ternary read chain over the expanded slots, so the new
 *       value is computed and DISCARDED — the mutation vanishes.</li>
 *   <li><b>Mutates-state recursion</b> — {@code AnfLower.exprMutatesState} has
 *       the identical guard, so the method is classified terminal and NO
 *       continuation assertion is injected at all: a method that mutates state
 *       emits nothing binding that mutation (no {@code get_state_script}, no
 *       output covenant, no continuation params).</li>
 * </ol>
 *
 * <p>The root cause is neither site: pass 3b rewrites only the increment's
 * OPERAND, leaving a {@code TernaryExpr} where both sites expect a property
 * access.
 *
 * <p>The control ({@code this.count++}, a plain scalar property) is the shape
 * that already works and must stay unchanged — it discriminates the two paths.
 */
class N019IndexIncrementStateMutationTest {

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    /** Runtime index ({@code i} is a parameter): a dispatch/ternary chain. */
    private static final String INDEX_INCREMENT = """
        class BumpIncr extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];

          constructor() {
            super();
          }

          public bump(i: bigint) {
            this.board[i]++;
          }
        }
        """;

    private static final String INDEX_DECREMENT = """
        class BumpDecr extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];

          constructor() {
            super();
          }

          public bump(i: bigint) {
            this.board[i]--;
          }
        }
        """;

    /** The hand-written form {@code this.board[i]++} must be equivalent to. */
    private static final String INDEX_EXPLICIT_ADD = """
        class BumpIncr extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];

          constructor() {
            super();
          }

          public bump(i: bigint) {
            this.board[i] = this.board[i] + 1n;
          }
        }
        """;

    /** Literal index — folds to {@code this.board__0}; must be unchanged. */
    private static final String LITERAL_INDEX_INCREMENT = """
        class BumpLit extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];

          constructor() {
            super();
          }

          public bump(i: bigint) {
            this.board[0]++;
          }
        }
        """;

    private static final String LITERAL_INDEX_EXPLICIT = """
        class BumpLit extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];

          constructor() {
            super();
          }

          public bump(i: bigint) {
            this.board[0] = this.board[0] + 1n;
          }
        }
        """;

    /** The plausible real-world shape: a histogram bump inside a loop. */
    private static final String INDEX_INCREMENT_IN_LOOP = """
        class BumpLoop extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];

          constructor() {
            super();
          }

          public bumpAll() {
            for (let i: bigint = 0n; i < 3n; i++) {
              this.board[i]++;
            }
          }
        }
        """;

    /** Control: the already-working shape, a plain mutable scalar property. */
    private static final String PLAIN_PROP_INCREMENT = """
        class BumpProp extends StatefulSmartContract {
          count: bigint = 0n;

          constructor() {
            super();
          }

          public bump(i: bigint) {
            this.count++;
          }
        }
        """;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static ContractNode parse(String source) throws Exception {
        return ParserDispatch.parse(source, "Test.runar.ts");
    }

    /** Parse + run pass 3b, exactly as the pipeline does before ANF lowering. */
    private static ContractNode expanded(String source) throws Exception {
        ExpandFixedArrays.Result result = ExpandFixedArrays.runCollecting(parse(source));
        assertTrue(result.errors().isEmpty(), "expand-fixed-arrays errors: " + result.errors());
        return result.contract();
    }

    private static AnfMethod anfMethod(String source, String method) throws Exception {
        AnfProgram program = AnfLower.run(expanded(source));
        return program.methods().stream()
            .filter(m -> m.name().equals(method))
            .findFirst()
            .orElseThrow(() -> new AssertionError("method " + method + " not found"));
    }

    /** Every update_prop name anywhere, including inside if arms and loops. */
    private static void updatePropNames(List<AnfBinding> bindings, List<String> out) {
        for (AnfBinding b : bindings) {
            AnfValue v = b.value();
            if (v instanceof UpdateProp up) {
                out.add(up.name());
            } else if (v instanceof If iff) {
                updatePropNames(iff.thenBranch(), out);
                updatePropNames(iff.elseBranch(), out);
            } else if (v instanceof Loop lp) {
                updatePropNames(lp.body(), out);
            }
        }
    }

    private static List<String> updatedProps(String source, String method) throws Exception {
        List<String> out = new ArrayList<>();
        updatePropNames(anfMethod(source, method).body(), out);
        return out;
    }

    private static List<String> paramNames(String source, String method) throws Exception {
        return anfMethod(source, method).params().stream().map(AnfParam::name).toList();
    }

    private static void collectKinds(List<AnfBinding> bindings, List<String> out) {
        for (AnfBinding b : bindings) {
            AnfValue v = b.value();
            out.add(v.kind());
            if (v instanceof If iff) {
                collectKinds(iff.thenBranch(), out);
                collectKinds(iff.elseBranch(), out);
            } else if (v instanceof Loop lp) {
                collectKinds(lp.body(), out);
            }
        }
    }

    /** The continuation covenant itself: is the spend bound to a state script? */
    private static boolean hasStateContinuation(String source, String method) throws Exception {
        List<String> kinds = new ArrayList<>();
        collectKinds(anfMethod(source, method).body(), kinds);
        return kinds.contains("get_state_script");
    }

    private static String anfText(String source) throws Exception {
        return AnfLower.run(expanded(source)).toString();
    }

    private static boolean anySlot(List<String> props, String prefix) {
        return props.stream().anyMatch(p -> p.startsWith(prefix));
    }

    // ------------------------------------------------------------------
    // Control — the shape that already works. Passes before AND after.
    // ------------------------------------------------------------------

    @Test
    void controlPlainPropertyIncrementUpdatesState() throws Exception {
        List<String> props = updatedProps(PLAIN_PROP_INCREMENT, "bump");
        assertTrue(props.contains("count"),
            "control regressed: `this.count++` produced no update_prop; got " + props);
        assertTrue(hasStateContinuation(PLAIN_PROP_INCREMENT, "bump"),
            "control regressed: `this.count++` emitted no get_state_script");
    }

    // ------------------------------------------------------------------
    // Half 1 — lowering: the increment through an index must update_prop.
    // ------------------------------------------------------------------

    @Test
    void indexIncrementEmitsUpdateProp() throws Exception {
        List<String> props = updatedProps(INDEX_INCREMENT, "bump");
        assertFalse(props.isEmpty(),
            "`this.board[i]++` produced NO update_prop at all — the mutation was "
                + "computed and discarded");
        assertTrue(anySlot(props, "board"),
            "`this.board[i]++` produced no update_prop for a board slot; got " + props);
    }

    @Test
    void indexDecrementEmitsUpdateProp() throws Exception {
        List<String> props = updatedProps(INDEX_DECREMENT, "bump");
        assertTrue(anySlot(props, "board"),
            "`this.board[i]--` produced no update_prop for a board slot; got " + props);
    }

    // ------------------------------------------------------------------
    // Half 2 — the method is NOT terminal: a continuation covenant exists.
    // ------------------------------------------------------------------

    @Test
    void indexIncrementIsAStateMutation() throws Exception {
        assertTrue(hasStateContinuation(INDEX_INCREMENT, "bump"),
            "`this.board[i]++` emitted no get_state_script: NOTHING binds the spending path");
    }

    @Test
    void indexDecrementIsAStateMutation() throws Exception {
        assertTrue(hasStateContinuation(INDEX_DECREMENT, "bump"),
            "`this.board[i]--` emitted no get_state_script");
    }

    @Test
    void indexIncrementInsideALoopIsAStateMutation() throws Exception {
        List<String> props = updatedProps(INDEX_INCREMENT_IN_LOOP, "bumpAll");
        assertTrue(anySlot(props, "board"),
            "`this.board[i]++` inside a for-loop produced no update_prop; got " + props);
        assertTrue(hasStateContinuation(INDEX_INCREMENT_IN_LOOP, "bumpAll"),
            "loop-bumping method emitted no get_state_script");
    }

    // ------------------------------------------------------------------
    // The desugar must be FAITHFUL, not merely present.
    // ------------------------------------------------------------------

    @Test
    void indexIncrementLowersIdenticallyToTheExplicitAdd() throws Exception {
        assertEquals(anfText(INDEX_EXPLICIT_ADD), anfText(INDEX_INCREMENT),
            "`this.board[i]++` must lower identically to `this.board[i] = this.board[i] + 1n`");
    }

    @Test
    void literalIndexIncrementIsUnchanged() throws Exception {
        assertEquals(anfText(LITERAL_INDEX_EXPLICIT), anfText(LITERAL_INDEX_INCREMENT),
            "literal-index `this.board[0]++` must stay byte-identical to the explicit form");
    }

    @Test
    void indexIncrementMethodGetsContinuationParams() throws Exception {
        assertEquals(paramNames(PLAIN_PROP_INCREMENT, "bump"), paramNames(INDEX_INCREMENT, "bump"),
            "`this.board[i]++` must receive the same continuation params as `this.count++`");
    }

    // ------------------------------------------------------------------
    // Expression position cannot write back through the dispatch chain.
    // ------------------------------------------------------------------

    @Test
    void indexIncrementInExpressionPositionIsRejected() throws Exception {
        // The TS surface parser rejects an assignment whose value is a postfix
        // increment, so drive the AST directly: an assignment whose value is an
        // IncrementExpr over an IndexAccessExpr.
        ContractNode contract = parse(INDEX_INCREMENT);
        MethodNode bump = contract.methods().stream()
            .filter(m -> m.name().equals("bump"))
            .findFirst()
            .orElseThrow();
        ExpressionStatement stmt = (ExpressionStatement) bump.body().get(0);
        List<Statement> body = List.of(new AssignmentStatement(
            new PropertyAccessExpr("board__0"), stmt.expression(), stmt.sourceLocation()));
        MethodNode patched = new MethodNode(
            bump.name(), bump.params(), body,
            bump.visibility(), bump.sourceLocation(), bump.sighashType());
        List<MethodNode> methods = new ArrayList<>(contract.methods());
        methods.set(methods.indexOf(bump), patched);
        ContractNode patchedContract = new ContractNode(
            contract.name(), contract.parentClass(), contract.properties(),
            contract.constructor(), methods, contract.sourceFile());

        ExpandFixedArrays.Result result = ExpandFixedArrays.runCollecting(patchedContract);
        assertFalse(result.errors().isEmpty(),
            "`x = this.board[i]++` was accepted; the array write is silently dropped");
    }
}
