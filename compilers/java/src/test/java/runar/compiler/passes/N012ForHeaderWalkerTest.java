package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.TsParser;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.VariableDeclStatement;

/**
 * N-012 -- the validator's expression walker covers a {@code for} loop's header.
 *
 * <p>Proves: the walker behind the asm() gate visits all three header slots of
 * a {@code for} statement (init, condition and update), so an {@code asm(...)}
 * call planted in any of them in a non-Unsafe contract is refused. The AST is
 * hand-built (the parsed records are rebuilt with the call planted) because the
 * for-update and literal-init rules make these shapes unreachable from source
 * today.
 *
 * <p>Does not prove: that any source program can reach this; only that a future
 * loosening of those rules cannot reopen the asm gate through the walker.
 */
class N012ForHeaderWalkerTest {

    private static final String SOURCE = """
        class C extends SmartContract {
          readonly t: bigint;
          constructor(t: bigint) { super(t); this.t = t; }
          public verify(a: bigint) {
            let s: bigint = 0n;
            for (let i: bigint = 0n; i < 3n; i++) { s = s + a; }
            assert(s === this.t);
          }
        }
        """;

    private static final String DIAG =
        "'asm' is only available in contracts extending UnsafeSmartContract";

    private static CallExpr asmCall() {
        return new CallExpr(new Identifier("asm"), List.of());
    }

    private static List<String> errorsWithAsmIn(String slot) throws TsParser.ParseException {
        ContractNode contract = TsParser.parse(SOURCE, "C.runar.ts");
        MethodNode method = contract.methods().get(0);
        List<Statement> body = new ArrayList<>();
        boolean planted = false;
        for (Statement s : method.body()) {
            if (s instanceof ForStatement f) {
                VariableDeclStatement init = f.init();
                var cond = f.condition();
                Statement update = f.update();
                switch (slot) {
                    case "init" -> init = new VariableDeclStatement(
                        init.name(), init.type(), asmCall(), init.sourceLocation());
                    case "condition" -> cond = asmCall();
                    default -> update = new ExpressionStatement(asmCall(), f.sourceLocation());
                }
                s = new ForStatement(init, cond, update, f.body(), f.sourceLocation());
                planted = true;
            }
            body.add(s);
        }
        assertTrue(planted, "no ForStatement in method body");
        MethodNode rebuilt = new MethodNode(
            method.name(), method.params(), body, method.visibility(),
            method.sourceLocation(), method.sighashType());
        List<MethodNode> methods = new ArrayList<>(contract.methods());
        methods.set(0, rebuilt);
        ContractNode mutated = new ContractNode(
            contract.name(), contract.parentClass(), contract.properties(),
            contract.constructor(), methods, contract.sourceFile());
        Validate.Result result = Validate.runCollecting(mutated);
        assertNotNull(result);
        return result.errors();
    }

    private static void assertRefused(String slot) throws TsParser.ParseException {
        List<String> errors = errorsWithAsmIn(slot);
        assertTrue(
            errors.stream().anyMatch(e -> e.contains(DIAG)),
            "asm() in for-loop " + slot + " was not refused; got " + errors);
    }

    @Test
    void asmInForInitIsRefused() throws TsParser.ParseException {
        assertRefused("init");
    }

    @Test
    void asmInForConditionIsRefused() throws TsParser.ParseException {
        assertRefused("condition");
    }

    @Test
    void asmInForUpdateIsRefused() throws TsParser.ParseException {
        assertRefused("update");
    }
}
