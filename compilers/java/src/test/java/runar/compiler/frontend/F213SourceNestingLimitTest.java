package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import runar.compiler.Cli;

/**
 * F-213 — one shared source-nesting limit, MAX_SOURCE_NESTING = 128, on all 9
 * surfaces, refused with the shared diagnostic
 * {@code source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)}.
 *
 * <p>Pre-fix the hand-written parsers had no depth bound: 1000 nested parens
 * threw StackOverflowError out of GoParser/PyParser/... (a JVM stack trace,
 * exit 1), and the javac-backed .runar.java path answered with whatever javac
 * or the converter hit first.
 *
 * <p>Proves, for every surface, at the canonical shapes of the spec
 * ({@code result = <expr>} as a method's top-level statement): n=126 nested
 * parens and n=126 nested {@code if}s compile end to end through the CLI
 * (exit 0, non-empty hex); n=127 of either, a 128-term {@code a + a + ...}
 * chain, and n=63/64 nested unary minus sit exactly on the boundary; a
 * 20000-deep shape of each kind is refused with the shared diagnostic and no
 * StackOverflowError — both through {@link ParserDispatch#parse} and through
 * the per-format exported entry point.
 *
 * <p>Does NOT prove: that the hex at the limit is byte-identical to the TS
 * reference (remediation-logs/F-213/check_tier.py checks that against the
 * built jar), nor the 500000-term chain (same harness), nor type nesting.
 */
class F213SourceNestingLimitTest {

    private static final String DIAG =
        "source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)";

    // ---------------------------------------------------------------
    // Source generators (mirror remediation-logs/F-213/gen.py)
    // ---------------------------------------------------------------

    private static String head(String ext) {
        switch (ext) {
            case "ts":
                return "import { SmartContract, assert } from 'runar-lang';\n\n"
                    + "class P extends SmartContract {\n"
                    + "  readonly limit: bigint;\n"
                    + "  constructor(limit: bigint) { super(limit); this.limit = limit; }\n"
                    + "  public check(value: bigint, mode: boolean): void {\n"
                    + "    let result: bigint = 0n;\n{BODY}\n"
                    + "    assert(result > 0n);\n  }\n}\n";
            case "sol":
                return "pragma runar ^0.1.0;\n\ncontract P is SmartContract {\n"
                    + "    int immutable limit;\n"
                    + "    constructor(int _limit) { limit = _limit; }\n"
                    + "    function check(int value, bool mode) public {\n"
                    + "        int result = 0;\n{BODY}\n"
                    + "        require(result > 0);\n    }\n}\n";
            case "move":
                return "module P {\n    use runar::types::{Int};\n"
                    + "    struct P { limit: Int, }\n"
                    + "    public fun check(contract: &P, value: Int, mode: bool) {\n"
                    + "        let result: Int = 0;\n{BODY}\n"
                    + "        assert!(result > 0, 0);\n    }\n}\n";
            case "go":
                return "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\n"
                    + "type P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:\"readonly\"`\n}\n\n"
                    + "func (c *P) Check(value runar.Int, mode runar.Bool) {\n"
                    + "\tresult := runar.Int(0)\n{BODY}\n"
                    + "\trunar.Assert(result > 0)\n}\n";
            case "rs":
                return "use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n"
                    + "    #[readonly]\n    limit: Int,\n}\n\nimpl P {\n"
                    + "    pub fn check(&self, value: Int, mode: bool) {\n"
                    + "        let mut result: Int = 0;\n{BODY}\n"
                    + "        assert!(result > 0);\n    }\n}\n";
            case "py":
                return "from runar import SmartContract, Bigint, public, assert_\n\n"
                    + "class P(SmartContract):\n    limit: Bigint\n\n"
                    + "    def __init__(self, limit: Bigint):\n"
                    + "        super().__init__(limit)\n        self.limit = limit\n\n"
                    + "    @public\n    def check(self, value: Bigint, mode: bool):\n"
                    + "        result: Bigint = 0\n{BODY}\n"
                    + "        assert_(result > 0)\n";
            case "zig":
                return "const runar = @import(\"runar\");\n\npub const P = struct {\n"
                    + "    pub const Contract = runar.SmartContract;\n    limit: i64,\n"
                    + "    pub fn init(limit: i64) P { return .{ .limit = limit }; }\n"
                    + "    pub fn check(self: *const P, value: i64, mode: bool) void {\n"
                    + "        var result: i64 = 0;\n{BODY}\n"
                    + "        runar.assert(result > 0);\n    }\n};\n";
            case "rb":
                return "require 'runar'\n\nclass P < Runar::SmartContract\n"
                    + "  prop :limit, Bigint\n\n  def initialize(limit)\n"
                    + "    super(limit)\n    @limit = limit\n  end\n\n"
                    + "  runar_public value: Bigint, mode: Boolean\n"
                    + "  def check(value, mode)\n    result = 0\n{BODY}\n"
                    + "    assert result > 0\n  end\nend\n";
            case "java":
                return "package p;\n\nimport runar.lang.SmartContract;\n"
                    + "import runar.lang.annotations.Public;\n"
                    + "import runar.lang.annotations.Readonly;\n"
                    + "import runar.lang.types.Bigint;\n\n"
                    + "import static runar.lang.Builtins.assertThat;\n\n"
                    + "class P extends SmartContract {\n    @Readonly Bigint limit;\n"
                    + "    P(Bigint limit) { super(limit); this.limit = limit; }\n"
                    + "    @Public\n    void check(Bigint value, boolean mode) {\n"
                    + "        Bigint result = Bigint.ZERO;\n{BODY}\n"
                    + "        assertThat(result.gt(Bigint.ZERO));\n    }\n}\n";
            default:
                throw new IllegalArgumentException(ext);
        }
    }

    private static String assign(String ext, String expr) {
        switch (ext) {
            case "go": return "\tresult = " + expr;
            case "py": return "        result = " + expr;
            case "rb": return "    result = " + expr;
            case "ts": return "    result = " + expr + ";";
            default: return "        result = " + expr + ";";
        }
    }

    private static String rep(String s, int n) {
        return String.join("", Collections.nCopies(n, s));
    }

    private static String parens(String ext, int n) {
        return head(ext).replace("{BODY}", assign(ext, rep("(", n) + "value" + rep(")", n)));
    }

    private static String neg(String ext, int n) {
        return head(ext).replace("{BODY}", assign(ext, rep("-(", n) + "value" + rep(")", n)));
    }

    private static String chain(String ext, int k) {
        return head(ext).replace("{BODY}", assign(ext, String.join(" + ", Collections.nCopies(k, "value"))));
    }

    private static String nestedIf(String ext, int n) {
        String inner = assign(ext, "value").strip();
        StringBuilder b = new StringBuilder();
        switch (ext) {
            case "py":
                for (int i = 0; i < n; i++) b.append("        ").append(rep(" ", i)).append("if mode:\n");
                b.append("        ").append(rep(" ", n)).append(inner);
                break;
            case "rb":
                b.append(rep("if mode\n", n)).append(inner).append('\n').append(rep("end\n", n));
                break;
            case "go":
            case "rs":
                b.append(rep("if mode {\n", n)).append(inner).append('\n').append(rep("}\n", n));
                break;
            case "move":
                b.append(rep("if (mode) {\n", n)).append(inner).append('\n').append(rep("};\n", n));
                break;
            default:
                b.append(rep("if (mode) {\n", n)).append(inner).append('\n').append(rep("}\n", n));
        }
        return head(ext).replace("{BODY}", b.toString());
    }

    private static String file(String ext) {
        return "P.runar." + ext;
    }

    // ---------------------------------------------------------------
    // Drivers
    // ---------------------------------------------------------------

    @TempDir
    Path tmp;

    /** Full CLI compile (parse .. emit); asserts exit 0 and a hex line. */
    private void assertCompiles(String ext, String src) throws Exception {
        Path p = tmp.resolve(file(ext));
        Files.writeString(p, src);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exit = new Cli(new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8))
            .run(new String[] {"--source", p.toString(), "--hex"});
        String e = err.toString(StandardCharsets.UTF_8);
        assertEquals(0, exit, ext + ": expected the at-limit source to compile, stderr: " + e);
        assertFalse(out.toString(StandardCharsets.UTF_8).isBlank(), ext + ": no hex emitted");
        assertFalse(e.contains(DIAG), ext + ": at-limit source refused: " + e);
    }

    /** Refusal with the shared diagnostic through the dispatcher. */
    private static void assertRefused(String ext, String src) {
        try {
            ParserDispatch.parse(src, file(ext));
            fail(ext + ": expected refusal with \"" + DIAG + "\", but the source parsed");
        } catch (ParserDispatch.ParseException e) {
            assertTrue(String.valueOf(e.getMessage()).contains(DIAG),
                ext + ": refused for the wrong reason: " + e.getMessage());
        } catch (StackOverflowError e) {
            fail(ext + ": StackOverflowError instead of the shared diagnostic");
        }
    }

    /** Refusal with the shared diagnostic through the per-format exported entry. */
    private static void assertRefusedDirect(String ext, String src) {
        String f = file(ext);
        try {
            switch (ext) {
                case "ts": TsParser.parse(src, f); break;
                case "sol": SolParser.parse(src, f); break;
                case "move": MoveParser.parse(src, f); break;
                case "go": GoParser.parse(src, f); break;
                case "rs": RustParser.parse(src, f); break;
                case "py": PyParser.parse(src, f); break;
                case "zig": ZigParser.parse(src, f); break;
                case "rb": RbParser.parse(src, f); break;
                case "java": JavaParser.parse(src, f); break;
                default: throw new IllegalArgumentException(ext);
            }
            fail(ext + ": per-format entry accepted an over-nested source");
        } catch (StackOverflowError e) {
            fail(ext + ": per-format entry threw StackOverflowError instead of the shared diagnostic");
        } catch (Exception e) {
            assertTrue(String.valueOf(e.getMessage()).contains(DIAG),
                ext + ": per-format entry refused for the wrong reason: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------

    @Test
    void constantMirrorsTheSchema() {
        assertEquals(128, InputLimits.MAX_SOURCE_NESTING);
    }

    @ParameterizedTest(name = "parensBoundary {0}")
    @ValueSource(strings = {"ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"})
    void parensBoundary(String ext) throws Exception {
        assertCompiles(ext, parens(ext, 126));
        assertRefused(ext, parens(ext, 127));
    }

    @ParameterizedTest(name = "nestedIfBoundary {0}")
    @ValueSource(strings = {"ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"})
    void nestedIfBoundary(String ext) throws Exception {
        assertCompiles(ext, nestedIf(ext, 126));
        assertRefused(ext, nestedIf(ext, 127));
    }

    @ParameterizedTest(name = "unaryBoundary {0}")
    @ValueSource(strings = {"ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"})
    void unaryBoundary(String ext) throws Exception {
        assertCompiles(ext, neg(ext, 63));
        assertRefused(ext, neg(ext, 64));
    }

    @ParameterizedTest(name = "chainBoundary {0}")
    @ValueSource(strings = {"ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"})
    void chainBoundary(String ext) throws Exception {
        assertCompiles(ext, chain(ext, 127));
        assertRefused(ext, chain(ext, 128));
        assertRefusedDirect(ext, chain(ext, 128));
    }

    @ParameterizedTest(name = "deepShapesRefusedWithoutCrash {0}")
    @ValueSource(strings = {"ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"})
    void deepShapesRefusedWithoutCrash(String ext) {
        // 20000 levels of Python indentation alone exceed MAX_SOURCE_BYTES.
        int ifDepth = ext.equals("py") ? 2500 : 20000;
        assertRefused(ext, parens(ext, 20000));
        assertRefused(ext, nestedIf(ext, ifDepth));
        assertRefused(ext, neg(ext, 20000));
        assertRefused(ext, chain(ext, 20000));
        assertRefusedDirect(ext, parens(ext, 20000));
        assertRefusedDirect(ext, nestedIf(ext, ifDepth));
    }
}
