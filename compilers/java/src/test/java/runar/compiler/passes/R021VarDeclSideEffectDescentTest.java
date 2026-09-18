package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;

/**
 * R-021 (CL-BUG-155): the continuation-shape walkers must descend into
 * variable-declaration initialisers.
 *
 * <p>{@code AnfLower.stmtMutatesState}, {@code stmtHasAddOutput} and
 * {@code stmtHasAddDataOutput} handled only {@code ExpressionStatement} /
 * {@code IfStatement} / {@code ForStatement} / {@code ReturnStatement}. A
 * {@code VariableDeclStatement} was invisible, so a side effect reachable only
 * through a variable-declaration initialiser never reached the
 * {@code needsChange} / {@code needsNewAmount} / {@code isTerminal} decision.
 *
 * <p>The four tiers that ship a dedicated {@code side_effect_summary} module
 * (TS, Go, Rust, Python) walk the initialiser, so this is a cross-tier
 * divergence, and it is unsafe in both of its shapes:
 *
 * <ol>
 *   <li><b>Output intrinsic behind the initialiser</b> — the private helper IS
 *       ANF-inlined (the inline test asks the HELPER, which does see its own
 *       {@code addOutput}), so the body emits the add_output node and loads
 *       {@code _changePKH}, but the method header never declared it. Stack
 *       lowering then refuses with "method parameter '_changePKH' is not on the
 *       stack" — a hard failure on valid Rúnar that four other tiers accept.</li>
 *   <li><b>State mutation behind the initialiser</b> — mutation-only helpers are
 *       NOT inlined, so nothing trips. The method is silently classified
 *       TERMINAL: no continuation params, no state continuation, no covenant.
 *       The deployed script binds NOTHING about where the value goes and a
 *       spender can take the whole UTXO anywhere. Silent, and a funds bug.</li>
 * </ol>
 *
 * <p>The expected parameter lists below are the TypeScript reference compiler's
 * own ABI for the same sources.
 */
class R021VarDeclSideEffectDescentTest {

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    /** Shape 1: {@code this.addOutput} reachable only via a var-decl initialiser. */
    private static final String VARDECL_OUTPUT = """
        class VarDeclOutput extends StatefulSmartContract {
          a: bigint;

          constructor(a: bigint) {
            super(a);
            this.a = a;
          }

          private emitAndReturn(amount: bigint): bigint {
            this.addOutput(1000n, this.a);
            return amount;
          }

          public settle(amount: bigint) {
            const paid: bigint = this.emitAndReturn(amount);
            assert(paid > 0n);
          }
        }
        """;

    /** Shape 2: a state mutation reachable only via a var-decl initialiser. */
    private static final String VARDECL_MUTATION = """
        class VarDeclMutation extends StatefulSmartContract {
          a: bigint;

          constructor(a: bigint) {
            super(a);
            this.a = a;
          }

          private bump(x: bigint): bigint {
            this.a = this.a + 1n;
            return x;
          }

          public settle(amount: bigint) {
            const paid: bigint = this.bump(amount);
            assert(paid > 0n);
          }
        }
        """;

    /** Control: the same effect reached from a bare expression statement. */
    private static final String STMT_OUTPUT = """
        class StmtOutput extends StatefulSmartContract {
          a: bigint;

          constructor(a: bigint) {
            super(a);
            this.a = a;
          }

          private emitAndReturn(amount: bigint): bigint {
            this.addOutput(1000n, this.a);
            return amount;
          }

          public settle(amount: bigint) {
            this.emitAndReturn(amount);
            assert(amount > 0n);
          }
        }
        """;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static List<String> settleParams(String src, String file) throws Exception {
        ContractNode contract = PipelineTestSupport.parseValidated(src, file);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        anf = Cli.optimizeAnf(anf, /* disableConstantFolding */ true);
        AnfMethod settle = anf.methods().stream()
            .filter(m -> m.name().equals("settle"))
            .findFirst()
            .orElse(null);
        assertNotNull(settle, "settle missing from the lowered program");
        return settle.params().stream().map(AnfParam::name).toList();
    }

    // ------------------------------------------------------------------
    // Control — already green; guards against over-correction.
    // ------------------------------------------------------------------

    @Test
    void controlBareStatementOutputKeepsContinuationParams() throws Exception {
        assertEquals(
            List.of("amount", "_changePKH", "_changeAmount", "txPreimage"),
            settleParams(STMT_OUTPUT, "StmtOutput.runar.ts"),
            "control regressed: a bare-statement addOutput lost its continuation params");
    }

    // ------------------------------------------------------------------
    // Shape 1 — output intrinsic behind a var-decl initialiser.
    // ------------------------------------------------------------------

    @Test
    void varDeclOutputDeclaresChangeParams() throws Exception {
        assertEquals(
            List.of("amount", "_changePKH", "_changeAmount", "txPreimage"),
            settleParams(VARDECL_OUTPUT, "VarDeclOutput.runar.ts"),
            "an addOutput reached through a var-decl initialiser did not reach the "
                + "continuation-shape decision (TS/Go/Rust/Python all declare "
                + "_changePKH/_changeAmount here)");
    }

    /** And the whole pipeline must survive: today stack lowering refuses. */
    @Test
    void varDeclOutputCompilesToScript() throws Exception {
        String hex = PipelineTestSupport.hex(VARDECL_OUTPUT, "VarDeclOutput.runar.ts");
        assertNotNull(hex);
    }

    // ------------------------------------------------------------------
    // Shape 2 — state mutation behind a var-decl initialiser.
    // ------------------------------------------------------------------

    @Test
    void varDeclMutationIsNotTerminal() throws Exception {
        assertEquals(
            List.of("amount", "_changePKH", "_changeAmount", "_newAmount", "txPreimage"),
            settleParams(VARDECL_MUTATION, "VarDeclMutation.runar.ts"),
            "a state mutation reached through a var-decl initialiser was classified "
                + "TERMINAL: the deployed script carries no continuation covenant and a "
                + "spender can take the UTXO anywhere");
    }
}
