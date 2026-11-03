package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.Statement;

/**
 * N-471. After N-468 the Java source map matches the TypeScript reference on
 * every {@code examples/ts} contract, but {@code AnfLower.lowerStatement}
 * still differed from {@code 04-anf-lower.ts lowerStatement} in two location
 * rules that no example reaches:
 *
 * <ol>
 *   <li>TS sets {@code ctx.currentSourceLoc = undefined} when a statement is
 *       done. Java restored the PREVIOUS location in its {@code finally}.
 *       The two only differ when a statement is lowered into a context that
 *       is still emitting bindings for an enclosing statement, i.e. a private
 *       helper inlined by {@code inlinePrivateMethodCall} (if / for / ternary
 *       arms use fresh sub-contexts that start with no location). Inlining is
 *       gated on the helper having output side effects, so the shape below is
 *       a stateful private helper that calls {@code addOutput} and returns a
 *       value which the caller keeps computing with.</li>
 *   <li>TS assigns {@code ctx.currentSourceLoc = stmt.sourceLocation}
 *       unconditionally, so a statement with no location clears the inherited
 *       one. Java only assigned when the statement had one. No TS parser and
 *       no 03b rewrite produces a location-less statement, so no source text
 *       reaches this rule; it is exercised on a parsed AST with one
 *       statement's location nulled.</li>
 * </ol>
 *
 * <p>Test 1 proves: for the inline source below, the Java CLI's
 * {@code --emit-source-map} (fold off) maps exactly the opcodes, lines and
 * columns the TS tier maps; TS leaves the two opcodes emitted after the
 * inlined helper ({@code load_const 7n}, {@code min}) unmapped. The TS map is
 * pinned (regenerate with {@code runar compile InlLoc.runar.ts -o <dir>
 * --disable-constant-folding --emit-source-map <out.json>} on the exact text
 * below) and is not recomputed here.
 *
 * <p>Test 2 proves: a location-less statement inside an inlined helper emits
 * bindings with no location rather than the calling statement's (it nulls
 * the helper's FIRST statement so only rule 2, not rule 1, can explain a
 * leftover location).
 *
 * <p>Neither proves anything about fold-ON maps, other tiers, or other source
 * formats; the 90-example sweep is the broad check.
 */
class N471AnfLowerSourceLocationTest {

    // Line numbers below are pinned against this exact text.
    private static final String SRC = """
        import { StatefulSmartContract, assert, min } from 'runar-lang';

        class InlLoc extends StatefulSmartContract {
          counter: bigint;

          constructor(counter: bigint) {
            super(counter);
            this.counter = counter;
          }

          private fork(amount: bigint, leftover: bigint): bigint {
            this.addOutput(amount, leftover);
            return amount;
          }

          public go(m: bigint) {
            const r: bigint = min(this.fork(m, m), 7n);
            assert(r > 0n);
          }
        }
        """;

    /** TS reference map runs: {firstOpcode, lastOpcode, line, column}. */
    private static final int[][] TS_RUNS = {
        {102, 105, 17, 4}, {106, 168, 12, 4}, {169, 169, 13, 4}, {172, 174, 18, 4},
    };

    private static final Pattern MAPPING = Pattern.compile(
        "\"opcodeIndex\":\\s*(\\d+),\\s*\"sourceFile\":\\s*\"[^\"]*\",\\s*\"line\":\\s*(\\d+),\\s*\"column\":\\s*(\\d+)");

    @Test
    void javaSourceMapMatchesTsAfterInlinedHelper() throws IOException {
        Map<Integer, String> want = new TreeMap<>();
        for (int[] r : TS_RUNS) {
            for (int op = r[0]; op <= r[1]; op++) want.put(op, r[2] + ":" + r[3]);
        }
        Path dir = Files.createTempDirectory("n471-");
        Path src = dir.resolve("InlLoc.runar.ts");
        Path out = dir.resolve("map.json");
        try {
            Files.writeString(src, SRC);
            PrintStream o = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
            PrintStream e = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
            int exit = new Cli(o, e).run(new String[] {"--source", src.toString(), "--disable-constant-folding",
                "--emit-source-map", out.toString(), "--hex"});
            assertEquals(0, exit, "runar-java failed");
            Map<Integer, String> got = new TreeMap<>();
            Matcher m = MAPPING.matcher(Files.readString(out));
            while (m.find()) got.put(Integer.parseInt(m.group(1)), m.group(2) + ":" + m.group(3));
            TreeSet<Integer> all = new TreeSet<>(want.keySet());
            all.addAll(got.keySet());
            List<String> diffs = new ArrayList<>();
            for (int i : all) {
                String w = want.get(i);
                String g = got.get(i);
                if (w == null ? g != null : !w.equals(g)) diffs.add("#" + i + ": TS " + w + " / Java " + g);
            }
            assertTrue(diffs.isEmpty(), diffs.size() + " opcodes differ from the TS map: " + diffs);
        } finally {
            Files.deleteIfExists(src);
            Files.deleteIfExists(out);
            Files.deleteIfExists(dir);
        }
    }

    @Test
    void locationLessStatementInInlinedHelperClearsInheritedLocation() throws Exception {
        ContractNode parsed = ParserDispatch.parse(SRC, "InlLoc.runar.ts");
        Validate.run(parsed);
        Typecheck.run(parsed);

        // Null the location of the helper's FIRST statement (`this.addOutput(...)`)
        // only. It runs while the calling statement's location is still current,
        // so a Java that keeps the inherited location stamps it with that.
        List<MethodNode> methods = new ArrayList<>();
        for (MethodNode m : parsed.methods()) {
            if (m.name().equals("fork")) {
                List<Statement> body = new ArrayList<>(m.body());
                assertTrue(body.get(0) instanceof ExpressionStatement, "fork must start with the addOutput call");
                body.set(0, new ExpressionStatement(((ExpressionStatement) body.get(0)).expression(), null));
                m = new MethodNode(m.name(), m.params(), body, m.visibility(), m.sourceLocation(), m.sighashType());
            }
            methods.add(m);
        }
        ContractNode c = new ContractNode(
            parsed.name(), parsed.parentClass(), parsed.properties(), parsed.constructor(), methods, parsed.sourceFile());

        AnfProgram prog = AnfLower.run(c);
        AnfMethod go = prog.methods().stream().filter(m -> m.name().equals("go")).findFirst().orElseThrow();
        List<AnfBinding> body = go.body();
        int addOutput = -1;
        for (int i = 0; i < body.size(); i++) {
            if (body.get(i).value().getClass().getSimpleName().equals("AddOutput")) {
                addOutput = i;
                break;
            }
        }
        assertTrue(addOutput >= 0 && addOutput + 1 < body.size(), "inlined add_output not found");
        // TS: the location-less statement overwrites the inherited location with none.
        assertNull(body.get(addOutput).sourceLoc(),
            "add_output of a location-less statement must carry no location, got "
                + body.get(addOutput).sourceLoc());
        // The next statement (`return amount;`, line 13) stamps its own.
        assertNotNull(body.get(addOutput + 1).sourceLoc());
        assertEquals(13, body.get(addOutput + 1).sourceLoc().line());
    }
}
