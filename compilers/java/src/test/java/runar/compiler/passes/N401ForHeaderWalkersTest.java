package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.TsParser;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.VariableDeclStatement;

/**
 * N-401 -- the validator's statement walkers cover a {@code for} loop's header.
 *
 * <p>Proves: the method-call collector (behind the recursion check) and the
 * output-intrinsic search (behind the no-addOutput-in-a-loop rule) visit all
 * three header slots of a {@code for} statement (init, condition and update). A
 * {@code this.m()} call planted only in a header slot is seen by the call graph
 * (so self-recursion through a header is refused), and an {@code addOutput}
 * planted only in a NESTED loop's header is found from the enclosing loop. The
 * AST is hand-built (the parsed records are rebuilt with the call planted)
 * because the for-update and literal-init rules make these shapes unreachable
 * from source today.
 *
 * <p>Does not prove: that any source program can reach these shapes today.
 */
class N401ForHeaderWalkersTest {

    private static final String PLAIN_SOURCE = """
        class C extends SmartContract {
          readonly t: bigint;
          constructor(t: bigint) { super(t); this.t = t; }
          public m(a: bigint) {
            let s: bigint = 0n;
            for (let i: bigint = 0n; i < 3n; i++) { s = s + a; }
            assert(s === this.t);
          }
        }
        """;

    private static final String NESTED_SOURCE = """
        class C extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public m(a: bigint) {
            let s: bigint = 0n;
            for (let i: bigint = 0n; i < 3n; i++) {
              for (let j: bigint = 0n; j < 3n; j++) { s = s + a; }
            }
            this.count = s;
          }
        }
        """;

    private static CallExpr thisCall(String name) {
        return new CallExpr(new PropertyAccessExpr(name), List.of());
    }

    private static ForStatement plant(ForStatement f, String slot, Expression expr) {
        VariableDeclStatement init = f.init();
        Expression cond = f.condition();
        Statement update = f.update();
        switch (slot) {
            case "init" -> init = new VariableDeclStatement(
                init.name(), init.type(), expr, init.sourceLocation());
            case "condition" -> cond = expr;
            default -> update = new ExpressionStatement(expr, f.sourceLocation());
        }
        return new ForStatement(init, cond, update, f.body(), f.sourceLocation());
    }

    private static List<String> validateWithPlanted(String source, boolean nested, String slot, String callee)
        throws TsParser.ParseException {
        ContractNode contract = TsParser.parse(source, "C.runar.ts");
        MethodNode method = contract.methods().get(0);
        List<Statement> body = new ArrayList<>();
        boolean planted = false;
        for (Statement s : method.body()) {
            if (s instanceof ForStatement f) {
                if (nested) {
                    List<Statement> innerBody = new ArrayList<>();
                    for (Statement is : f.body()) {
                        if (is instanceof ForStatement inner) {
                            is = plant(inner, slot, thisCall(callee));
                            planted = true;
                        }
                        innerBody.add(is);
                    }
                    s = new ForStatement(f.init(), f.condition(), f.update(), innerBody, f.sourceLocation());
                } else {
                    s = plant(f, slot, thisCall(callee));
                    planted = true;
                }
            }
            body.add(s);
        }
        assertTrue(planted, "no ForStatement planted");
        MethodNode rebuilt = new MethodNode(
            method.name(), method.params(), body, method.visibility(),
            method.sourceLocation(), method.sighashType());
        List<MethodNode> methods = new ArrayList<>(contract.methods());
        methods.set(0, rebuilt);
        ContractNode mutated = new ContractNode(
            contract.name(), contract.parentClass(), contract.properties(),
            contract.constructor(), methods, contract.sourceFile());
        return Validate.runCollecting(mutated).errors();
    }

    private static void assertRecursionSeen(String slot) throws TsParser.ParseException {
        List<String> errors = validateWithPlanted(PLAIN_SOURCE, false, slot, "m");
        assertTrue(
            errors.stream().anyMatch(e -> e.toLowerCase().contains("recursion detected")),
            "call in for-loop " + slot + " was not collected; got " + errors);
    }

    private static void assertIntrinsicFound(String slot) throws TsParser.ParseException {
        List<String> errors = validateWithPlanted(NESTED_SOURCE, true, slot, "addOutput");
        assertTrue(
            errors.stream().anyMatch(e -> e.contains("Output intrinsic 'addOutput'")),
            "addOutput in nested for-loop " + slot + " was not found; got " + errors);
    }

    @Test
    void callInForInitIsCollected() throws TsParser.ParseException {
        assertRecursionSeen("init");
    }

    @Test
    void callInForConditionIsCollected() throws TsParser.ParseException {
        assertRecursionSeen("condition");
    }

    @Test
    void callInForUpdateIsCollected() throws TsParser.ParseException {
        assertRecursionSeen("update");
    }

    @Test
    void addOutputInNestedForInitIsFound() throws TsParser.ParseException {
        assertIntrinsicFound("init");
    }

    @Test
    void addOutputInNestedForConditionIsFound() throws TsParser.ParseException {
        assertIntrinsicFound("condition");
    }

    @Test
    void addOutputInNestedForUpdateIsFound() throws TsParser.ParseException {
        assertIntrinsicFound("update");
    }
}
