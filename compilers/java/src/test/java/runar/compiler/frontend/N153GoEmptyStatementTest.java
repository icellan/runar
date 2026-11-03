package runar.compiler.frontend;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-153 -- a .runar.go EMPTY statement {@code ;} is refused, as in the TS
 * reference.
 *
 * <p>Pre-fix this tier (with the Rust and Python tiers) skipped every
 * {@code ;} in a block, so {@code ;} on its own line, {@code stmt; ;} and
 * {@code if c { ; }} compiled; the TS reference and the Go tier (go/parser
 * EmptyStmt) refuse them with "Unexpected token in expression: ';'". A
 * {@code ;} that ends a statement on the same line still separates it from the
 * next one, as go/parser accepts; whether that separator should be accepted
 * at all (TS refuses it) is left open in the N-153 report.
 *
 * <p>Proves: this tier's .runar.go parser refuses each empty-statement shape
 * with the TS diagnostic and still parses the same-line separator.
 * Does not prove: other tiers (conformance/negatives/
 * n153-statement-shape-parity.test.ts) or other surfaces.
 */
class N153GoEmptyStatementTest {

    private static final String WANT = "Unexpected token in expression: ';'";

    private static String errorsOf(String stmt) {
        String src = "package contract\n\n"
            + "import runar \"github.com/icellan/runar/packages/runar-go\"\n\n"
            + "type Disc struct {\n"
            + "\trunar.SmartContract\n"
            + "\tT runar.Bigint `runar:\"readonly\"`\n"
            + "}\n\n"
            + "func (c *Disc) Unlock(x runar.Bigint) {\n"
            + "\t" + stmt + "\n"
            + "\trunar.Assert(true)\n"
            + "}\n\n"
            + "func (c *Disc) check(x runar.Bigint) runar.Bigint {\n"
            + "\trunar.Assert(x == c.T)\n"
            + "\treturn x\n"
            + "}\n";
        try {
            GoParser.parse(src, "Disc.runar.go");
            return "";
        } catch (GoParser.ParseException e) {
            return e.getMessage();
        }
    }

    @Test
    void emptyStatementIsRefusedWithTheTsDiagnostic() {
        List<String> failures = new ArrayList<>();
        for (String stmt : new String[] {
            ";",
            "runar.Assert(x == c.T)\n\t;",
            "runar.Assert(x == c.T); ;",
            "runar.Assert(x == c.T);;",
            "if x == c.T { ; }",
        }) {
            String got = errorsOf(stmt);
            if (!got.contains(WANT)) failures.add("go `" + stmt + "`: got " + got);
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
    }

    @Test
    void sameLineSeparatorIsUnchanged() {
        List<String> failures = new ArrayList<>();
        for (String stmt : new String[] {
            "runar.Assert(x == c.T);",
            "y := c.check(x); _ = y",
            "if x == c.T { runar.Assert(true) };",
        }) {
            String got = errorsOf(stmt);
            if (!got.isEmpty()) failures.add("go `" + stmt + "`: " + got);
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
    }

    /** N-153 escalation decision: a {@code {} at statement start is refused. */
    @Test
    void statementStartingWithABraceIsRefused() {
        List<String> failures = new ArrayList<>();
        for (String stmt : new String[] {
            "{ runar.Assert(x == c.T) }",
            "{ x, c.check(x) }",
            "{ }",
            "{\n\t\ty := x\n\t\trunar.Assert(y == c.T)\n\t}",
            "if x == c.T {\n\t\t{ runar.Assert(true) }\n\t}",
        }) {
            String got = errorsOf(stmt);
            if (!got.contains("Unexpected token in expression: '{'")) failures.add("go `" + stmt + "`: got " + got);
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
        String lit = errorsOf("y := [2]runar.Bigint{x, c.T}\n\t_ = y");
        assertTrue(lit.isEmpty(), "expression-position literal: " + lit);
    }
}
