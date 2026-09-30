package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * F-064 — the .runar.ts surface refuses every statement kind outside
 * spec/grammar.md §9 with the TS reference's diagnostic,
 * "Unsupported statement kind: &lt;ts.SyntaxKind name&gt;", and never drops one.
 *
 * <p>Pre-fix this parser swallowed stray {@code ;} (skipSemicolons) and fell
 * through to the expression parser for every keyword it did not dispatch on:
 * {@code throw x;} / {@code debugger;} / {@code break;} became identifier
 * expressions a later pass happened to reject, and a nested {@code ;} compiled.
 *
 * <p>Proves: the Java .runar.ts parser refuses each kind (top level, nested in
 * if, in a for body) with the shared diagnostic. Does not prove: the other
 * Java-tier surfaces (.runar.java/.sol/.move/...).
 */
class F064TsUnsupportedStatementTest {

    private static final String[][] CASES = {
        {"while (x > 0n) { assert(false); }", "WhileStatement"},
        {"do { assert(false); } while (x > 0n);", "DoStatement"},
        {"switch (x) { case 1n: assert(false); break; default: assert(false); }", "SwitchStatement"},
        {"outer: for (let i = 0n; i < 2n; i++) { assert(false); }", "LabeledStatement"},
        {"try { assert(false); } catch (e) { assert(false); }", "TryStatement"},
        {"throw x;", "ThrowStatement"},
        {"for (const k in this) { assert(false); }", "ForInStatement"},
        {"for (const k of [x]) { assert(false); }", "ForOfStatement"},
        {"{ assert(false); }", "Block"},
        {";", "EmptyStatement"},
        {"assert(x > 1n);;", "EmptyStatement"},
        {"const y = x;;", "EmptyStatement"},
        {"class Inner { }", "ClassDeclaration"},
        {"function inner(): void { assert(false); }", "FunctionDeclaration"},
        {"debugger;", "DebuggerStatement"},
        {"with (x) { assert(false); }", "WithStatement"},
        {"break;", "BreakStatement"},
        {"continue;", "ContinueStatement"},
    };

    private static final String[] CONTEXTS = {
        "%s",
        "if (x > 0n) { %s }",
        "for (let j = 0n; j < 2n; j++) { %s }",
    };

    private static String wrap(String stmt) {
        return "import { SmartContract, assert } from 'runar-lang';\n\n"
            + "class Probe extends SmartContract {\n"
            + "  readonly a: bigint;\n\n"
            + "  constructor(a: bigint) {\n"
            + "    super(a);\n"
            + "    this.a = a;\n"
            + "  }\n\n"
            + "  public unlock(x: bigint) {\n"
            + "    " + stmt + "\n"
            + "    assert(x > this.a);\n"
            + "  }\n"
            + "}\n";
    }

    @Test
    void everyUnsupportedStatementKindIsRefusedWithTheSharedDiagnostic() {
        List<String> failures = new ArrayList<>();
        for (String[] c : CASES) {
            for (String ctx : CONTEXTS) {
                String body = String.format(ctx, c[0]);
                String want = "Unsupported statement kind: " + c[1];
                try {
                    TsParser.parse(wrap(body), "Probe.runar.ts");
                    failures.add(body + ": accepted");
                } catch (TsParser.ParseException e) {
                    if (!e.getMessage().contains(want)) {
                        failures.add(body + ": want \"" + want + "\", got " + e.getMessage());
                    }
                }
            }
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
    }

    @Test
    void wellFormedBodyStillParses() {
        assertDoesNotThrow(() -> TsParser.parse(wrap("const y = x + 1n;\n    assert(y > 0n);"), "Probe.runar.ts"));
    }
}
