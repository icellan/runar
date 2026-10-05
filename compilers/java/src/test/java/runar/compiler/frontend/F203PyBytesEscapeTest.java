package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.ExpressionStatement;
import org.junit.jupiter.api.Test;

/**
 * F-203 (CL-BUG-208..213) — .runar.py byte literals decode escapes the way
 * CPython bytes literals do.
 *
 * <p>Pre-fix this tier decoded {@code \0} to one byte (as the Python tier did)
 * while TS and Go emitted the two bytes 5c 30, and every other escape
 * ({@code \n}, {@code \t}, {@code \\}, ...) was hex-encoded character by
 * character, so a {@code len(tag) == 1} check passed under pytest (CPython)
 * and failed on-chain.
 *
 * <p>The rule is the TS reference's (packages/runar-compiler/src/passes/
 * 01-parse-python.ts, decodePyLiteral): b'..' / b".." decode
 * {@code \\ \' \" \a \b \f \n \r \t \v}, octal {@code \NNN} (1-3 digits, at
 * most 0o377) and {@code \xHH} (two hex digits, kept verbatim); any other
 * escape is refused with "invalid escape sequence '&lt;escape&gt;'"; a non-ASCII
 * character in a bytes literal with "bytes can only contain ASCII literal
 * characters"; plain '..' strings decode the same escapes and refuse
 * backslash-N, backslash-u, backslash-U. Expected bytes are CPython's own
 * ({@code python3 -c "print(b'..'.hex())"}).
 *
 * <p>What this proves: this tier's .runar.py frontend turns each escaped
 * literal into CPython's bytes and refuses each undefined or unsupported form
 * with the shared diagnostic at the literal's line.
 * What it does not prove: the other six tiers (their suites and
 * conformance/negatives/py-bytes-escape-parity.test.ts), or the emitted script
 * (the parity test compares script hex across tiers).
 */
class F203PyBytesEscapeTest {

    private static final String FILE = "Esc.runar.py";

    private static String contract(String lit) {
        return "from runar import SmartContract, ByteString, public, assert_\n\n\n"
            + "class Esc(SmartContract):\n    def __init__(self):\n        super().__init__()\n\n"
            + "    @public\n    def unlock(self, x: ByteString):\n        assert_(x == " + lit + ")\n";
    }

    /** {Python body between b'..', the literal's hex: CPython's bytes, \xHH spelled verbatim}. */
    private static final String[][] BYTES_CASES = {
        {"\\0", "00"},
        {"\\00", "00"},
        {"\\000", "00"},
        {"\\7", "07"},
        {"\\101", "41"},
        {"\\377", "ff"},
        {"\\1234", "5334"},
        {"a\\0b", "610062"},
        {"\\08", "0038"},
        {"\\n", "0a"},
        {"\\t", "09"},
        {"\\r", "0d"},
        {"\\\\", "5c"},
        {"\\'", "27"},
        {"\\\"", "22"},
        {"\\a", "07"},
        {"\\b", "08"},
        {"\\f", "0c"},
        {"\\v", "0b"},
        {"\\xde\\xAD", "deAD"},
        {"\\x00\\x6a", "006a"},
        {"ab", "6162"},
        {"\\\\n", "5c6e"},
        {"x\\ty\\nz", "7809790a7a"},
    };

    private static String literal(String lit) throws Exception {
        ContractNode c = PyParser.parse(contract(lit), FILE);
        ExpressionStatement st = (ExpressionStatement) c.methods().get(0).body().get(0);
        BinaryExpr eq = (BinaryExpr) ((CallExpr) st.expression()).args().get(0);
        return ((ByteStringLiteral) eq.right()).value();
    }

    private static String refusal(String source) {
        try {
            ParserDispatch.parse(source, FILE);
            return null;
        } catch (ParserDispatch.ParseException e) {
            return e.getMessage();
        }
    }

    @Test
    void sharedDiagnostics() {
        assertEquals("invalid escape sequence '\\q'", LexDiag.invalidEscapeSequence("\\q"));
        assertEquals("bytes can only contain ASCII literal characters", LexDiag.PY_BYTES_NON_ASCII);
    }

    @Test
    void bytesEscapesDecodeToCPythonBytes() throws Exception {
        for (String[] c : BYTES_CASES) {
            assertEquals(c[1], literal("b'" + c[0] + "'"), "b'" + c[0] + "'");
        }
        assertEquals("2722", literal("b\"\\'\\\"\""), "both escaped quotes inside double quotes");
    }

    @Test
    void plainStringDecodesEscapesBeforeTheHexCheck() throws Exception {
        assertEquals("ab", literal("\"\\x61\\x62\""));
    }

    @Test
    void refusals() {
        String[][] invalid = {
            {"b'\\q'", "\\q"},
            {"b'\\x4'", "\\x"},
            {"b'\\xg0'", "\\x"},
            {"b'\\400'", "\\400"},
            {"b'\\N{DIGIT ONE}'", "\\N"},
            {"b'\\u0041'", "\\u"},
            {"b'\\U00000041'", "\\U"},
            {"\"\\q\"", "\\q"},
            {"\"\\u0061\"", "\\u"},
        };
        for (String[] c : invalid) {
            String got = refusal(contract(c[0]));
            assertNotNull(got, c[0] + ": accepted");
            assertTrue(got.contains(FILE + ":10:") && got.contains("invalid escape sequence '" + c[1] + "'"),
                c[0] + ": got " + got);
        }
        String got = refusal(contract("b'\u00e9'"));
        assertNotNull(got, "non-ASCII accepted");
        assertTrue(got.contains("bytes can only contain ASCII literal characters"), got);
        for (String lit : new String[] {"rb'\\n'", "br'\\n'", "B'\\n'", "r'ab'", "u'ab'", "f'ab'"}) {
            assertNotNull(refusal(contract(lit)), lit + ": accepted");
        }
        assertNotNull(refusal(contract("b'ab\\\ncd'")), "backslash-newline continuation accepted");
    }
}
