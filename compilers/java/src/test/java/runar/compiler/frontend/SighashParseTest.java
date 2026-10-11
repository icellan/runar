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
        assertNull(methodByName(src, "bump").sighashType());
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
