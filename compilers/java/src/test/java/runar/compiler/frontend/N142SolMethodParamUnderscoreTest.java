package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import runar.compiler.Cli;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParamNode;
import runar.compiler.ir.ast.PropertyAccessExpr;

/**
 * N-142 (Java twin of F-200) — .runar.sol leading-underscore stripping
 * applies to CONSTRUCTOR params only.
 *
 * <p>{@code SolParser.parseSolParams} used to strip a leading {@code _} from
 * every parameter, but only {@code parseSolConstructor} renames its body to
 * match. So a METHOD param {@code _x} was declared as {@code x} while the
 * body still read {@code _x}:
 * <ul>
 *   <li>unbound: {@code function check(bigint _x) public { require(_x == target); }}
 *       failed typecheck (TS compiles it);</li>
 *   <li>silent: {@code function inc(bigint _count) public { count++; }}
 *       declared a param {@code count} that shadowed the property, so the
 *       bare {@code count++} bumped the param and the state write was
 *       silently dropped (a different script, no diagnostic);</li>
 *   <li>inter: both at once.</li>
 * </ul>
 * The rule is the TS reference's ({@code 01-parse-sol.ts}):
 * {@code parseConstructor} strips {@code _} and renames the body;
 * {@code parseFunction} keeps param names verbatim.
 *
 * <p>What this proves: in the Java tier, method params keep their {@code _}
 * name, the constructor still strips it, the bare {@code count++} stays a
 * property write, and all three shapes compile through the CLI (fold-ON
 * default) to the TS reference bytes (sha256-pinned, the same pins as
 * conformance/negatives/sol-method-param-underscore-parity.test.ts).
 *
 * <p>What it does NOT prove: other tiers (the 7-tier pin lives in that
 * conformance test), fold-OFF output, or on-chain spend behaviour.
 */
class N142SolMethodParamUnderscoreTest {

    private static final String UNBOUND = "pragma runar ^0.1.0;\n\n"
        + "contract F200Unbound is SmartContract {\n"
        + "    bigint immutable target;\n\n"
        + "    constructor(bigint _target) {\n"
        + "        target = _target;\n"
        + "    }\n\n"
        + "    function check(bigint _x) public {\n"
        + "        require(_x == target);\n"
        + "    }\n"
        + "}\n";

    private static final String SILENT = "pragma runar ^0.1.0;\n\n"
        + "contract F200Silent is StatefulSmartContract {\n"
        + "    bigint count;\n\n"
        + "    constructor(bigint _count) {\n"
        + "        count = _count;\n"
        + "    }\n\n"
        + "    function inc(bigint _count) public {\n"
        + "        count++;\n"
        + "    }\n"
        + "}\n";

    private static final String INTER = "pragma runar ^0.1.0;\n\n"
        + "contract F200Inter is StatefulSmartContract {\n"
        + "    bigint count;\n\n"
        + "    constructor(bigint _count) {\n"
        + "        count = _count;\n"
        + "    }\n\n"
        + "    function inc(bigint _count) public {\n"
        + "        count++;\n"
        + "        require(_count > 0);\n"
        + "    }\n"
        + "}\n";

    private static MethodNode method(ContractNode c, String name) {
        for (MethodNode m : c.methods()) {
            if (m.name().equals(name)) return m;
        }
        throw new AssertionError("no method " + name);
    }

    private static List<String> names(List<ParamNode> ps) {
        return ps.stream().map(ParamNode::name).toList();
    }

    @Test
    void methodParamKeepsUnderscoreAndConstructorStrips() throws Exception {
        ContractNode c = ParserDispatch.parse(UNBOUND, "F200Unbound.runar.sol");
        assertEquals(List.of("_x"), names(method(c, "check").params()));
        assertEquals(List.of("target"), names(c.constructor().params()));
    }

    @Test
    void unboundShapeCompilesToTsBytes(@TempDir Path dir) throws Exception {
        assertEquals("009c", hex(dir, "F200Unbound.runar.sol", UNBOUND));
    }

    @Test
    void silentShapeWritesState(@TempDir Path dir) throws Exception {
        MethodNode inc = method(ParserDispatch.parse(SILENT, "F200Silent.runar.sol"), "inc");
        assertEquals(List.of("_count"), names(inc.params()));
        IncrementExpr ie = assertInstanceOf(IncrementExpr.class,
            assertInstanceOf(ExpressionStatement.class, inc.body().get(0)).expression());
        assertEquals(new PropertyAccessExpr("count"), ie.operand());
        assertEquals("484142b25662c6a0a0126f11b1d4700fd79632224dc38c6ae869c889e5fe30d5",
            sha256(hex(dir, "F200Silent.runar.sol", SILENT)));
    }

    @Test
    void interShapeCompilesToTsBytes(@TempDir Path dir) throws Exception {
        assertEquals("29956ebf68e8510b65a74f18a47e5851f322bf6dc2d0981b45ee301f2aaae575",
            sha256(hex(dir, "F200Inter.runar.sol", INTER)));
    }

    private static String hex(Path dir, String file, String src) throws Exception {
        Path p = dir.resolve(file);
        Files.writeString(p, src);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exit = new Cli(new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8)).run(new String[] {"--source", p.toString(), "--hex"});
        assertEquals(0, exit, file + ": " + err.toString(StandardCharsets.UTF_8));
        return out.toString(StandardCharsets.UTF_8).trim().toLowerCase();
    }

    private static String sha256(String s) throws Exception {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
    }
}
