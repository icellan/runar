package runar.compiler.frontend;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-056 (CL-BUG-192) -- .runar.go operator precedence differed across tiers.
 *
 * <p>The Go tier parses .runar.go with go/parser (Go precedence); this tier,
 * the TS reference and the other four use the C ladder, so {@code a & b + 1}
 * was {@code (a & b) + 1} in one tier and {@code a & (b + 1)} in the rest.
 * R51: every tier refuses an unparenthesised mix whose grouping differs
 * between the two schemes, with the shared diagnostic from 01-parse-go.ts.
 * The oracle recomputes the 72 ambiguous ordered operator pairs from the two
 * precedence tables rather than reusing the parser's constant.
 *
 * <p>Proves: this tier refuses every ambiguous pair with the shared text,
 * accepts the 252 agreeing pairs and both parenthesisations, and treats
 * {@code &^} as {@code &} and call results as operands.
 * Does not prove: emitted bytes or the other tiers (conformance negatives
 * N175-N179 and the agreeing-pairs control cover cross-tier agreement).
 */
class N056GoAmbiguousPrecedenceTest {

    private static final Map<String, Integer> GO_PREC = new LinkedHashMap<>();
    private static final Map<String, Integer> C_PREC = new LinkedHashMap<>();

    static {
        for (String op : new String[] {"*", "/", "%", "<<", ">>", "&"}) GO_PREC.put(op, 5);
        for (String op : new String[] {"+", "-", "|", "^"}) GO_PREC.put(op, 4);
        for (String op : new String[] {"==", "!=", "<", "<=", ">", ">="}) GO_PREC.put(op, 3);
        GO_PREC.put("&&", 2);
        GO_PREC.put("||", 1);
        for (String op : new String[] {"*", "/", "%"}) C_PREC.put(op, 10);
        for (String op : new String[] {"+", "-"}) C_PREC.put(op, 9);
        for (String op : new String[] {"<<", ">>"}) C_PREC.put(op, 8);
        for (String op : new String[] {"<", "<=", ">", ">="}) C_PREC.put(op, 7);
        for (String op : new String[] {"==", "!="}) C_PREC.put(op, 6);
        C_PREC.put("&", 5);
        C_PREC.put("^", 4);
        C_PREC.put("|", 3);
        C_PREC.put("&&", 2);
        C_PREC.put("||", 1);
    }

    private static String message(String x, String y) {
        return "ambiguous operator precedence in .runar.go: `a " + x + " b " + y + " c` groups differently "
            + "under Go precedence than in Rúnar's other surfaces; add parentheses";
    }

    /** Returns the joined parse errors, or "" when the source parses. */
    private static String errorsOf(String expr) {
        String src = "package contract\n\n"
            + "import runar \"github.com/icellan/runar/packages/runar-go\"\n\n"
            + "type Probe struct {\n"
            + "\trunar.SmartContract\n"
            + "\tT runar.Int `runar:\"readonly\"`\n"
            + "}\n\n"
            + "func (c *Probe) Unlock(a runar.Int, b runar.Int, d runar.Int) {\n"
            + "\tx := " + expr + "\n"
            + "\trunar.Assert(x == c.T)\n"
            + "}\n";
        try {
            GoParser.parse(src, "Probe.runar.go");
            return "";
        } catch (GoParser.ParseException e) {
            return e.getMessage();
        }
    }

    private static void refused(List<String> failures, String expr, String x, String y) {
        String got = errorsOf(expr);
        if (!got.contains(message(x, y))) failures.add(expr + " not refused: " + got);
    }

    private static void accepted(List<String> failures, String expr) {
        String got = errorsOf(expr);
        if (!got.isEmpty()) failures.add(expr + ": " + got);
    }

    @Test
    void everyAmbiguousPairRefusedAndAgreeingPairAccepted() {
        int conflicts = 0;
        int agree = 0;
        List<String> failures = new ArrayList<>();
        for (String x : GO_PREC.keySet()) {
            for (String y : GO_PREC.keySet()) {
                String expr = "a " + x + " b " + y + " d";
                boolean goLeft = GO_PREC.get(x) >= GO_PREC.get(y);
                boolean cLeft = C_PREC.get(x) >= C_PREC.get(y);
                if (goLeft != cLeft) {
                    conflicts++;
                    refused(failures, expr, x, y);
                    accepted(failures, "(a " + x + " b) " + y + " d");
                    accepted(failures, "a " + x + " (b " + y + " d)");
                } else {
                    agree++;
                    accepted(failures, expr);
                }
            }
        }
        assertEquals(List.of(72, 252), List.of(conflicts, agree));
        assertTrue(failures.isEmpty(), failures.size() + " failures:\n" + String.join("\n", failures));
    }

    @Test
    void probes() {
        List<String> failures = new ArrayList<>();
        refused(failures, "a & b + 1", "&", "+");
        refused(failures, "a + b << 2", "+", "<<");
        refused(failures, "a | b + d", "|", "+");
        refused(failures, "a & 255 == 15", "&", "==");
        accepted(failures, "a ^ b * d");
        refused(failures, "(a & b + 1) * d", "&", "+");
        refused(failures, "runar.Abs(a + b << 2)", "+", "<<");
        refused(failures, "a * (d + (a | b + d))", "|", "+");
        accepted(failures, "a + b * d - a");
        refused(failures, "a * b + d << 1", "+", "<<");
        accepted(failures, "a &^ b");
        refused(failures, "a &^ b + d", "&", "+");
        accepted(failures, "(a &^ b) + d");
        accepted(failures, "runar.BigintBigAdd(a, b) << 2");
        accepted(failures, "runar.Abs(a + b) << 2");
        refused(failures, "-a + b << 2", "+", "<<");
        accepted(failures, "-(a + b) << 2");
        assertTrue(failures.isEmpty(), failures.size() + " failures:\n" + String.join("\n", failures));
    }
}
