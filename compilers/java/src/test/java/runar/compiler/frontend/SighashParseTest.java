package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch.ParseException;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.MethodNode;

/** Issue #123 — {@code @sighash} directive parsing on the .runar.ts surface. */
class SighashParseTest {

    private static MethodNode methodByName(String src, String name) throws ParseException {
        ContractNode c = ParserDispatch.parse(src, "X.runar.ts");
        for (MethodNode m : c.methods()) {
            if (m.name().equals(name)) {
                return m;
            }
        }
        throw new IllegalStateException("method not found: " + name);
    }

    @Test
    void setsSighashTypeFromJsdocDirective() throws Exception {
        String src =
            "class C extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  /** @sighash SINGLE|FORKID */\n"
            + "  public bump(): void { this.n = this.n + 1n; }\n"
            + "}\n";
        assertEquals(0x43, methodByName(src, "bump").sighashType());
    }

    @Test
    void leavesSighashTypeNullWhenNoDirective() throws Exception {
        String src =
            "class C extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  public bump(): void { this.n = this.n + 1n; }\n"
            + "}\n";
        assertNull(methodByName(src, "bump").sighashType());
    }

    @Test
    void acceptsLineCommentDirective() throws Exception {
        String src =
            "class C extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  // @sighash NONE|FORKID\n"
            + "  public wipe(): void { this.n = 0n; }\n"
            + "}\n";
        assertEquals(0x42, methodByName(src, "wipe").sighashType());
    }

    @Test
    void reportsErrorForBadFlagCombo() {
        String src =
            "class C extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  /** @sighash ALL|NONE|FORKID */\n"
            + "  public bump(): void { this.n = this.n + 1n; }\n"
            + "}\n";
        ParseException ex = assertThrows(ParseException.class,
            () -> ParserDispatch.parse(src, "X.runar.ts"));
        assertTrue(ex.getMessage().contains("cannot combine base types"), ex.getMessage());
    }

    /**
     * F-282: a `@sighash` comment that trails a method's OWN closing brace on
     * that method's own declaration line is a genuine trailing comment of that
     * method, not a leading directive for it — ts-morph's
     * `getLeadingCommentRanges()` / `getJsDocs()` never attach it (verified
     * directly against ts-morph: both come back empty for this exact source).
     * TsParser's line-only `collectLeadingComments(afterLine, memberLine)`
     * wrongly captured it because the comment's line equals `memberLine`
     * regardless of column, silently flipping the emitted sighash flag for a
     * method that asked for none. This test proves the over-inclusion is
     * fixed; it does not test the (already-correct, unchanged) case of a
     * directive sharing a line with the PRECEDING member, which ts-morph also
     * drops and which TsParser already dropped before this fix.
     */
    @Test
    void ignoresTrailingSameLineCommentAfterMethod() throws Exception {
        String src =
            "class C extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  public bump(): void { this.n = this.n + 1n; } // @sighash NONE|FORKID\n"
            + "}\n";
        // N-199 (R75): still not attached to bump, and the lost directive is
        // now refused instead of silently compiling under ALL|FORKID.
        ParseException ex = assertThrows(ParseException.class,
            () -> ParserDispatch.parse(src, "X.runar.ts"));
        assertEquals(expectedLost(src, "@sighash"), ex.getMessage());
    }

    // -----------------------------------------------------------------
    // N-199 (user decision R75): a `@sighash` / `@embedAlways` marker inside
    // the contract class body that is not in the leading comments of the
    // member kind that reads it (method / property) is refused with the
    // shared message, located at the marker's `@` (1-based line, 0-based
    // column).
    //
    // Proves: the Java TS-surface parser refuses each lost-directive shape the
    // TS reference refuses (sighash-parse.test.ts "N-199", Go
    // TestN199_LostDirectiveRefused) with the same text and location, and
    // still accepts attached directives and prose outside the class body.
    // Does not prove: cross-tier agreement (conformance/negatives/
    // n199-lost-directive-parity.test.ts does) or non-ASCII column units.
    // -----------------------------------------------------------------

    private static String lostMessage(String directive) {
        String target = directive.equals("@sighash") ? "method" : "property";
        return directive + " directive is not attached to any " + target
            + " and would be silently ignored; put the comment on its own line directly above the "
            + target + " it annotates (a comment that shares a line with the preceding code belongs to that code)";
    }

    private static String expectedLost(String src, String marker) {
        int idx = src.indexOf(marker);
        String before = src.substring(0, idx);
        int line = before.split("\n", -1).length;
        int col = idx - (before.lastIndexOf('\n') + 1);
        return "X.runar.ts:" + line + ":" + col + ": " + lostMessage(marker);
    }

    private static final String STATEFUL_HEAD =
        "import { StatefulSmartContract } from 'runar-lang';\n"
        + "export class C extends StatefulSmartContract {\n"
        + "  n: bigint;\n";
    private static final String CTOR = "  constructor(n: bigint) { super(n); this.n = n; }\n";
    private static final String BUMP = "  public bump(): void { this.addOutput(1000n, this.n); }";

    private static String stateful(String body) {
        return STATEFUL_HEAD + CTOR + body + "\n}\n";
    }

    @Test
    void n199RefusesLostDirectives() {
        String[][] cases = {
            {"line comment sharing a line with the preceding method",
                stateful("  private foo(): void {} // @sighash SINGLE|FORKID\n" + BUMP), "@sighash"},
            {"JSDoc sharing a line with the preceding method",
                stateful("  private foo(): void {} /** @sighash SINGLE|FORKID */\n" + BUMP), "@sighash"},
            {"end of class body",
                stateful(BUMP + "\n  /** @sighash SINGLE|FORKID */"), "@sighash"},
            {"inside a method body",
                stateful("  public bump(): void {\n    // @sighash SINGLE|FORKID\n    this.addOutput(1000n, this.n);\n  }"), "@sighash"},
            {"on a property",
                stateful("  /** @sighash SINGLE|FORKID */\n  readonly k: bigint = 1n;\n" + BUMP), "@sighash"},
            {"above the constructor",
                STATEFUL_HEAD + "  /** @sighash SINGLE|FORKID */\n" + CTOR + BUMP + "\n}\n", "@sighash"},
            {"@embedAlways sharing a line with the preceding property",
                "import { SmartContract, assert } from 'runar-lang';\n"
                + "export class C extends SmartContract {\n"
                + "  readonly a: bigint; // @embedAlways\n"
                + "  readonly tag: bigint;\n"
                + "  constructor(a: bigint, tag: bigint) { super(a, tag); this.a = a; this.tag = tag; }\n"
                + "  public go(x: bigint): void { assert(x == this.a); }\n"
                + "}\n", "@embedAlways"},
            {"@embedAlways on a method",
                "import { SmartContract, assert } from 'runar-lang';\n"
                + "export class C extends SmartContract {\n"
                + "  readonly a: bigint;\n"
                + "  constructor(a: bigint) { super(a); this.a = a; }\n"
                + "  /** @embedAlways */\n"
                + "  public go(x: bigint): void { assert(x == this.a); }\n"
                + "}\n", "@embedAlways"},
        };
        for (String[] c : cases) {
            ParseException ex = assertThrows(ParseException.class,
                () -> ParserDispatch.parse(c[1], "X.runar.ts"), c[0]);
            assertEquals(expectedLost(c[1], c[2]), ex.getMessage(), c[0]);
        }
    }

    @Test
    void n199AcceptsAttachedDirectivesAndProseOutsideClassBody() throws Exception {
        String src =
            "import { StatefulSmartContract } from 'runar-lang';\n"
            + "// File header prose: this contract uses @sighash SINGLE|FORKID and @embedAlways.\n"
            + "/** Class doc: `@sighash` lives on bump, `@embedAlways` on tag. */\n"
            + "export class C extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  /** @embedAlways */\n"
            + "  readonly tag: bigint;\n"
            + "  constructor(n: bigint, tag: bigint) { super(n, tag); this.n = n; this.tag = tag; }\n"
            + "  private foo(): void {}\n"
            + "  // @sighash SINGLE|FORKID\n"
            + BUMP + "\n"
            + "}\n";
        assertEquals(0x43, methodByName(src, "bump").sighashType());
    }

    @Test
    void reportsErrorForSighashOnPrivateMethod() {
        String src =
            "class C extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  /** @sighash SINGLE|FORKID */\n"
            + "  private helper(): bigint { return 1n; }\n"
            + "  public bump(): void { this.n = this.n + 1n; }\n"
            + "}\n";
        ParseException ex = assertThrows(ParseException.class,
            () -> ParserDispatch.parse(src, "X.runar.ts"));
        assertTrue(ex.getMessage().contains("non-public method"), ex.getMessage());
    }
}
