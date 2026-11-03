package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import runar.compiler.frontend.ParserDispatch.ParseException;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.MethodNode;

/**
 * F-039 — a present-but-malformed {@code @sighash} marker is a compile error.
 *
 * <p>Before F-039, {@code /** @sighash SINGLE|FORKID! *&#47;} (a one-character
 * typo) did not match the extractor regex, so the method was read as having NO
 * directive and compiled, silently, under the default ALL|FORKID. A second
 * directive on one method was silently ignored.
 *
 * <p>Proves: the Java TS-surface parser refuses each malformed / duplicated
 * shape with the diagnostic shared by all seven tiers (N-039: including
 * {@code @sighash} glued to the next token), and still honours a well-formed
 * multi-line JSDoc directive.
 * Does not prove: cross-tier agreement (conformance/negatives rejection-parity).
 */
class F039SighashMalformedTest {

    static final String MALFORMED =
        "Method 'bump': @sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a "
        + "|-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)";
    static final String MULTIPLE =
        "Method 'bump': @sighash: more than one @sighash directive on this method; declare exactly one";

    private static String src(String directive) {
        return "class C extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  " + directive + "\n"
            + "  public bump(): void { this.addOutput(1000n, this.n); }\n"
            + "}\n";
    }

    private static String rejection(String directive) {
        return assertThrows(ParseException.class,
            () -> ParserDispatch.parse(src(directive), "X.runar.ts")).getMessage();
    }

    private static MethodNode bump(String directive) throws ParseException {
        ContractNode c = ParserDispatch.parse(src(directive), "X.runar.ts");
        return c.methods().stream().filter(m -> m.name().equals("bump")).findFirst().orElseThrow();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/** @sighash SINGLE|FORKID! */",
        "/** @sighash:SINGLE|FORKID */",
        "// @sighash=SINGLE|FORKID",
        "/** @sighash SINGLE,FORKID */",
    })
    void malformedDirectiveRejected(String directive) {
        String msg = rejection(directive);
        assertTrue(msg.contains(MALFORMED), msg);
    }

    @Test
    void bareMarkerLineCommentRejected() {
        String msg = rejection("// @sighash");
        assertTrue(msg.contains(
            "Method 'bump': @sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)"), msg);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/** @sighash SINGLE|FORKID\n   * @sighash ALL|FORKID */",
        "/** @sighash SINGLE|FORKID */\n  /** @sighash ALL|FORKID */",
        "/** @sighash SINGLE|FORKID!\n   * @sighash NONE|FORKID */",
    })
    void multipleDirectivesRejected(String directive) {
        String msg = rejection(directive);
        assertTrue(msg.contains(MULTIPLE), msg);
        assertFalse(msg.contains("malformed directive"), msg);
    }

    // N-039 (user decision R85, "Refuse, all 7 tiers"): this used to pin the
    // word-boundary rule (@sighashSINGLE / @sighashType read as prose, so the
    // method silently got the default ALL|FORKID). A comment token that starts
    // with @sighash but is not exactly `@sighash <FLAGS>` is now refused with
    // the shared malformed diagnostic; the case list is unchanged plus _ / digit.
    @ParameterizedTest
    @ValueSource(strings = {
        "/** @sighashSINGLE|FORKID */",
        "/** see the @sighashType docs */",
        "// @sighash_SINGLE|FORKID",
        "/** @sighash2 */",
    })
    void n039GluedMarkerRejected(String directive) {
        String msg = rejection(directive);
        assertTrue(msg.contains(MALFORMED), msg);
    }

    @Test
    void wellFormedMultilineJsdocHonoured() throws Exception {
        assertEquals(0x43, bump("/**\n   * Bump.\n   * @sighash SINGLE|FORKID\n   */").sighashType());
    }
}
