package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * F-011 (CL-BUG-196) — an unterminated string or byte-string literal is
 * refused, never scanned onward into the lines that follow it.
 *
 * <p>Pre-fix, this tier's .runar.py tokenizer scanned {@code b"cafe} up to the
 * next matching quote, three lines down in a comment, so the guard
 * {@code assert_(y < 5)} became literal DATA and the emitted script had no
 * guard (@bsv/sdk Spend.validate accepted y = 100 against it; evidence in the
 * F-011 remediation log). Its other run-to-next-quote tokenizers swallowed the
 * next line the same way and its Ruby tokenizer ended a literal silently.
 *
 * <p>The rule is the TS reference's (packages/runar-compiler/src/errors.ts,
 * UNTERMINATED_STRING_LITERAL): a quoted literal that reaches a line break or
 * end of file before its closing quote is refused with exactly
 * "unterminated string literal" at its opening quote; on .runar.rs, for
 * Python triple-quoted strings, .runar.go backtick raw strings and .runar.ts
 * template literals only end of file counts; a Java char literal is refused
 * with "char literals are unsupported in Rúnar Java contracts".
 *
 * <p>What this proves: every hand-written surface of this tier refuses the
 * conformance negatives N52-N64 with that exact text at the opening quote's
 * line, and the closed-literal controls, Python docstrings, a Rust string and
 * a Go struct tag that span lines are not refused for it; the javac-based
 * .runar.java surface still refuses N59/N60 and refuses a terminated char
 * literal with the reference's text.
 * What it does not prove: anything about the other tiers (their suites and
 * conformance/negatives/rejection-parity.test.ts), or literal forms the
 * tokenizers never scanned (Rust raw strings, heredocs).
 */
class F011UnterminatedLiteralTest {

    private static final String MSG = "unterminated string literal";
    private static final String CHAR_MSG = "char literals are unsupported in Rúnar Java contracts";
    private static final Path NEGATIVES = Path.of("../../conformance/negatives");

    private record Fx(String file, int line, String open, String closed, String msg) {}

    private static final Fx[] FIXTURES = {
        new Fx("N52-py-bytes-unterminated-swallow.runar.py", 22, "b\"cafe\n", "b\"cafe\"\n", MSG),
        new Fx("N53-py-string-unterminated.runar.py", 13, "'cafe\n", "'cafe'\n", MSG),
        new Fx("N54-py-docstring-unterminated.runar.py", 19, "follows.\n", "follows.\"\"\"\n", MSG),
        new Fx("N55-sol-string-unterminated.runar.sol", 13, "\"cafe\n", "\"cafe\";\n", MSG),
        new Fx("N56-move-string-unterminated.runar.move", 12, "\"cafe\n", "\"cafe\";\n", MSG),
        new Fx("N57-zig-string-unterminated.runar.zig", 12, "\"cafe\n", "\"cafe\";\n", MSG),
        new Fx("N58-rs-string-unterminated.runar.rs", 13, "\"cafe;\n", "\"cafe\";\n", MSG),
        new Fx("N59-java-string-unterminated.runar.java", 22, "", "", null), // javac surface
        new Fx("N60-java-char-literal.runar.java", 21, "", "", null), // javac surface
        new Fx("N61-rb-single-quote-unterminated.runar.rb", 10, "'cafe\n", "'cafe'\n", MSG),
        new Fx("N62-rb-double-quote-unterminated.runar.rb", 9, "\"cafe\n", "\"cafe\"\n", MSG),
        new Fx("N63-go-string-unterminated.runar.go", 18, "\"cafe\n", "\"cafe\"\n", MSG),
        new Fx("N64-ts-string-unterminated.runar.ts", 14, "\"cafe;\n", "\"cafe\";\n", MSG),
    };

    /** The frontend's refusal message for {@code source}, or null if it parsed. */
    private static String refusal(String source, String file) {
        try {
            ParserDispatch.parse(source, file);
            return null;
        } catch (ParserDispatch.ParseException e) {
            return e.getMessage();
        }
    }

    private static void assertAt(String source, String file, String msg, int line) {
        String got = refusal(source, file);
        assertNotNull(got, file + ": accepted; want " + msg);
        Pattern p = Pattern.compile(Pattern.quote(file) + ":" + line + ":\\d+: " + Pattern.quote(msg));
        assertTrue(p.matcher(got).find(), file + ": want '" + msg + "' at line " + line + ", got: " + got);
    }

    private static void assertNotUnterminated(String source, String file) {
        String got = refusal(source, file);
        assertFalse(got != null && got.contains(MSG), file + ": refused as unterminated but it is not: " + got);
    }

    @Test
    void conformanceNegatives() throws IOException {
        for (Fx f : FIXTURES) {
            String src = Files.readString(NEGATIVES.resolve(f.file()));
            if (f.msg() == null) {
                assertNotNull(refusal(src, f.file()), f.file() + ": accepted");
                continue;
            }
            assertAt(src, f.file(), f.msg(), f.line());
            String ctl = src.replaceFirst(Pattern.quote(f.open()), java.util.regex.Matcher.quoteReplacement(f.closed()));
            assertNotEquals(src, ctl, f.file() + ": control replacement did not apply");
            assertNotUnterminated(ctl, f.file());
        }
    }

    private static final String PY_HEAD = "from runar import SmartContract, Bigint, ByteString, public, assert_\n\n\n"
        + "class G(SmartContract):\n    def __init__(self):\n        super().__init__()\n\n"
        + "    @public\n    def unlock(self, y: Bigint):\n";

    @Test
    void pythonShapes() {
        for (String lit : new String[] {"b\"ca", "b'ca", "\"ca", "'ca"}) {
            assertAt(PY_HEAD + "        t: ByteString = " + lit + "\n        assert_(y < 5)\n", "G.runar.py", MSG, 10);
            assertAt(PY_HEAD + "        assert_(y < 5)\n        t: ByteString = " + lit, "G.runar.py", MSG, 11);
        }
        assertAt(PY_HEAD + "        t: ByteString = b\"ca\\\n        assert_(y < 5)\n", "G.runar.py", MSG, 10);
        assertAt(PY_HEAD + "        assert_(y < 5)\n        x = \"\"\"note\n", "G.runar.py", MSG, 11);
        assertNotUnterminated(PY_HEAD + "        '''Method docstring\n        on two lines.'''\n        \"\"\"one line\"\"\"\n        assert_(y < 5)\n", "G.runar.py");
    }

    @Test
    void otherSurfaceShapes() {
        assertAt("pragma runar ^0.1.0;\ncontract G is SmartContract {\n  function f() public { 'ca", "G.runar.sol", MSG, 3);
        assertAt("module G {\n    public fun f(y: Int) {\n        let t: ByteString = b\"ca\\\n", "G.runar.move", MSG, 3);
        assertAt("const runar = @import(\"runar", "G.runar.zig", MSG, 1);
        assertAt("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\n  end\nend\n", "G.runar.rb", MSG, 4);
        assertNotUnterminated("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\"fe\"\n  end\nend\n", "G.runar.rb");
        assertAt("package contract\n\nfunc (c *G) F() {\n\tt := \"ca\\\n}\n", "G.runar.go", MSG, 4);
        assertAt("package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\"readonly\"\n}\n", "G.runar.go", MSG, 4);
        assertNotUnterminated("package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\n\"readonly\"`\n}\n", "G.runar.go");
        assertAt("import { SmartContract } from 'runar-lang\n", "G.runar.ts", MSG, 1);
        assertAt("class G extends SmartContract {\n  f(): void { const t = \"ca\n  }\n}\n", "G.runar.ts", MSG, 2);
        assertNotUnterminated("class G extends SmartContract {\n  f(): void { const t = \"ca\\\nfe\";\n  }\n}\n", "G.runar.ts");
        String rs = "use runar::prelude::*;\n\n#[runar::contract]\npub struct G {\n}\n\nimpl G {\n    pub fn unlock(&self, y: Bigint) {\n";
        assertAt(rs + "        let t: ByteString = \"ca\\\"\n        assert!(y < 5);\n    }\n}\n", "G.runar.rs", MSG, 9);
        assertNotUnterminated(rs + "        let t: ByteString = \"ca\nfe\";\n        assert!(y < 5);\n    }\n}\n", "G.runar.rs");
    }

    @Test
    void javacSurfaceRefusesACharLiteralWithTheReferenceText() {
        String src = "package g;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\n"
            + "import runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\n"
            + "class G extends SmartContract {\n    G() {\n        super();\n    }\n\n    @Public\n"
            + "    void unlock(Bigint y) {\n        assertThat(y.lt(Bigint.of('c')));\n    }\n}\n";
        String got = refusal(src, "G.runar.java");
        assertNotNull(got, "a char literal was accepted");
        assertTrue(got.contains(CHAR_MSG), "want '" + CHAR_MSG + "', got: " + got);
    }
}
