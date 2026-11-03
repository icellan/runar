package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import runar.compiler.Cli;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.Statement;

/**
 * N-137 — .runar.sol bare property references inside {@code ++} / {@code --}
 * and member expressions (the Java-tier twin of F-201).
 *
 * <p>Solidity lets a method name a state variable without {@code this.}. The
 * parser rewrites such bare identifiers to {@code PropertyAccessExpr}, but
 * {@code SolParser.rewriteBareProps} had no branch for {@code IncrementExpr},
 * {@code DecrementExpr} or {@code MemberExpr}: their operand / object kept a
 * bare {@code Identifier}. So in a StatefulSmartContract {@code count++;}
 * compiled to a script that bumps a phantom local and carries the OLD state
 * into the continuation output — a silent miscompile. The rule is the TS
 * reference's ({@code 01-parse-sol.ts resolvePropertyAccess}): recurse into
 * the operand of increment/decrement and the object of a member expression;
 * a parameter or in-scope local of the same name shadows the property.
 *
 * <p>What this proves: in the Java tier, the canonical Counter written with
 * bare {@code count++} / {@code ++count} / {@code count--} / {@code --count}
 * (and {@code +=} / {@code -=}) compiles (fold OFF) byte-identically to the
 * stateful-counter conformance golden that every tier produces from the
 * {@code this.count} form; the operands and member objects are rewritten to
 * property accesses at the AST level; a same-named parameter or local still
 * shadows the property.
 *
 * <p>What it does NOT prove: other tiers, or on-chain behaviour — the 7-tier
 * byte parity and the @bsv/sdk Spend state-advance check were run separately
 * and are recorded in the N-137 remediation log.
 */
class N137SolBarePropRewriteTest {

    private static final String FILE = "Counter.runar.sol";

    private static String counter(String increment, String decrement) {
        return "pragma runar ^0.1.0;\n\n"
            + "contract Counter is StatefulSmartContract {\n"
            + "    bigint count;\n\n"
            + "    constructor(bigint _count) {\n"
            + "        count = _count;\n"
            + "    }\n\n"
            + "    function increment() public {\n"
            + "        " + increment + "\n"
            + "    }\n\n"
            + "    function decrement() public {\n"
            + "        require(count > 0);\n"
            + "        " + decrement + "\n"
            + "    }\n"
            + "}\n";
    }

    @Test
    void bareCountersCompileToTheStatefulCounterGolden(@TempDir Path dir) throws Exception {
        String golden = Files.readString(Path.of("../../conformance/tests/stateful-counter/expected-script.hex")).trim();
        Map<String, String> variants = new LinkedHashMap<>();
        variants.put("postfix", counter("count++;", "count--;"));
        variants.put("prefix", counter("++count;", "--count;"));
        variants.put("compound", counter("count += 1;", "count -= 1;"));
        int i = 0;
        for (Map.Entry<String, String> e : variants.entrySet()) {
            Path p = dir.resolve("v" + (i++) + "-" + FILE);
            Files.writeString(p, e.getValue());
            String[] hex = run("--source", p.toString(), "--hex", "--disable-constant-folding");
            assertEquals("0", hex[0], e.getKey() + ": " + hex[2]);
            assertEquals(golden, hex[1].trim().toLowerCase(), e.getKey());
        }
    }

    private static List<Statement> body(String src, String method) throws Exception {
        for (MethodNode m : ParserDispatch.parse(src, FILE).methods()) {
            if (m.name().equals(method)) return m.body();
        }
        throw new AssertionError("no method " + method);
    }

    private static Expression expr(Statement s) {
        return assertInstanceOf(ExpressionStatement.class, s).expression();
    }

    @Test
    void updateOperandIsRewrittenToPropertyAccess() throws Exception {
        for (String stmt : new String[] {"count++;", "++count;"}) {
            IncrementExpr ie = assertInstanceOf(IncrementExpr.class, expr(body(counter(stmt, "count--;"), "increment").get(0)));
            assertEquals(new PropertyAccessExpr("count"), ie.operand(), stmt);
        }
        for (String stmt : new String[] {"count--;", "--count;"}) {
            DecrementExpr de = assertInstanceOf(DecrementExpr.class, expr(body(counter("count++;", stmt), "decrement").get(1)));
            assertEquals(new PropertyAccessExpr("count"), de.operand(), stmt);
        }
    }

    @Test
    void memberObjectIsRewrittenToPropertyAccess() throws Exception {
        CallExpr req = assertInstanceOf(CallExpr.class,
            expr(body(counter("require(count.length > 0);", "count--;"), "increment").get(0)));
        BinaryExpr gt = assertInstanceOf(BinaryExpr.class, req.args().get(0));
        assertEquals(new MemberExpr(new PropertyAccessExpr("count"), "length"), gt.left());
    }

    @Test
    void parameterShadowsTheProperty() throws Exception {
        String src = counter("count++;", "count--;").replace("function increment()", "function increment(bigint count)");
        IncrementExpr ie = assertInstanceOf(IncrementExpr.class, expr(body(src, "increment").get(0)));
        assertEquals(new Identifier("count"), ie.operand());
    }

    @Test
    void localShadowsTheProperty() throws Exception {
        String src = counter("bigint count = 5; count++;", "count--;");
        IncrementExpr ie = assertInstanceOf(IncrementExpr.class, expr(body(src, "increment").get(1)));
        assertEquals(new Identifier("count"), ie.operand());
        // ... but the property is still reached in a method without the local.
        DecrementExpr de = assertInstanceOf(DecrementExpr.class, expr(body(src, "decrement").get(1)));
        assertEquals(new PropertyAccessExpr("count"), de.operand());
    }

    private static String[] run(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, StandardCharsets.UTF_8);
        PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8);
        int exit = new Cli(o, e).run(args);
        return new String[] {
            String.valueOf(exit), out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8)
        };
    }
}
