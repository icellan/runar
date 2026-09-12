package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-101 — {@code <unknown>} in a boolean-CONDITION position.
 *
 * <p>The ninth instance of the class {@code bca3bb4f} (R-092) closed eight of,
 * and the one that commit named and left filed: this tier carried
 * {@code && !"<unknown>".equals(cond)} on the {@code if}, {@code for} and
 * ternary condition checks that its six peers do not. Measured:
 *
 * <pre>
 *   if (this.hp()) { ... }             6 tiers REJECT, java ACCEPT (24 hexchars)
 *   const y = this.hp() ? 1n : 2n;     6 tiers REJECT, java ACCEPT (22 hexchars)
 * </pre>
 *
 * <p>{@code this.hp()} is a private helper returning {@code PubKey}. No tier
 * derives a private method's declared return type ({@code MethodNode} carries no
 * {@code returnType}), so it infers as {@code <unknown>}. This tier then lowered
 * a 33-byte PubKey into a branch condition, where post-Genesis it is simply
 * truthy — the {@code if} the author wrote is not the {@code if} that ends up on
 * chain. Same soundness argument R-092 made for the operand positions, same
 * resolution: converge on the strict six, never on the permissive one.
 *
 * <p><b>{@code assert()} keeps its escape.</b> That one is not a divergence —
 * TS, Go, Rust, Python, Zig and Ruby all carry
 * {@code condType != BOOLEAN && condType != "<unknown>"} there, and all seven
 * tiers compile {@code assert(this.hp())} to the same 4 hexchars. Deleting it
 * would have broken parity in the other direction, which is why it is pinned as
 * a control below rather than swept up with the rest.
 *
 * <p>The {@code for} escape is deleted as DEAD CODE, not as a behaviour change:
 * this tier's validator requires a for-loop condition to be a comparison against
 * a compile-time constant and refuses {@code for (...; this.hp(); ...)} three
 * passes earlier. That is characterised below so the deletion is not mistaken
 * for an untested edit, exactly as bca3bb4f characterised its unreachable
 * {@code isSubtype} conjuncts.
 *
 * <p>The rejections are asserted through the SAME chain
 * {@code runar.lang.sdk.CompileCheck} runs, which is the distinction R-092 had
 * to fix once already: a frontend-only API must not green-light a source the
 * CLI refuses three passes later.
 */
class N101UnknownBooleanConditionTest {

    private static String withHelper(String body) {
        return """
            import { SmartContract, assert, PubKey } from 'runar-lang';
            class C extends SmartContract {
              readonly pk: PubKey;
              constructor(pk: PubKey) { super(pk); this.pk = pk; }
              private hp(): PubKey { return this.pk; }
            """
            + body
            + "}\n";
    }

    // --- REJECT ------------------------------------------------------------

    /** `if` condition inferred as `<unknown>`. */
    private static final String IF_COND = withHelper("""
          public go(x: bigint) {
            let y: bigint = 0n;
            if (this.hp()) {
              y = y + 1n;
            }
            assert(x > y);
          }
        """);

    /** Ternary condition inferred as `<unknown>`. */
    private static final String TERNARY_COND = withHelper("""
          public go(x: bigint) {
            const y: bigint = this.hp() ? 1n : 2n;
            assert(y > 0n);
          }
        """);

    // --- ACCEPT (over-rejection guards) ------------------------------------

    /**
     * The escape that STAYS. Every one of the seven tiers accepts this and
     * emits the same 4 hexchars; deleting the assert() escape would have
     * created a divergence rather than closed one.
     */
    private static final String ASSERT_UNKNOWN = withHelper("""
          public go(x: bigint) {
            assert(this.hp());
          }
        """);

    /** An ordinary boolean `if` condition must be unaffected. */
    private static final String IF_BOOLEAN = withHelper("""
          public go(x: bigint) {
            let y: bigint = 0n;
            if (x > 1n) {
              y = y + 1n;
            }
            assert(x > y);
          }
        """);

    /** An ordinary boolean ternary condition must be unaffected. */
    private static final String TERNARY_BOOLEAN = withHelper("""
          public go(x: bigint) {
            const y: bigint = x > 1n ? 1n : 2n;
            assert(y > 0n);
          }
        """);

    /** An ordinary bounded `for` loop must be unaffected. */
    private static final String FOR_BOUNDED = withHelper("""
          public go(x: bigint) {
            let y: bigint = 0n;
            for (let i: bigint = 0n; i < 3n; i++) {
              y = y + 1n;
            }
            assert(x > y);
          }
        """);

    // -----------------------------------------------------------------------

    /** The exact chain {@code runar.lang.sdk.CompileCheck} runs. */
    private static List<String> frontendErrors(String src) throws Exception {
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        Validate.run(c);
        c = ExpandFixedArrays.run(c);
        return Typecheck.collect(c);
    }

    private static void assertRejected(String src, String needle) throws Exception {
        List<String> errs = frontendErrors(src);
        assertFalse(
            errs.isEmpty(),
            "expected the Java frontend to REJECT this source; it accepted it. "
                + "Six tiers reject it — Java accepting it is the N-101 divergence."
        );
        assertTrue(
            errs.stream().anyMatch(e -> e.contains(needle)),
            "expected a diagnostic containing \"" + needle + "\", got " + errs
        );
    }

    // --- the defect --------------------------------------------------------

    @Test
    void ifConditionRejectsUnknown() throws Exception {
        assertRejected(IF_COND, "if condition must be boolean, got '<unknown>'");
    }

    @Test
    void ternaryConditionRejectsUnknown() throws Exception {
        assertRejected(TERNARY_COND, "ternary condition must be boolean, got '<unknown>'");
    }

    /**
     * Characterisation, not a rule: the third deleted escape (the for-loop
     * condition) is unreachable from source because Validate refuses the shape
     * first. If the validator is ever relaxed, this test fails and the
     * typechecker's own rule — now un-escaped — becomes the thing that catches
     * it.
     */
    @Test
    void forConditionNeverReachesTheTypechecker() throws Exception {
        String src = withHelper("""
              public go(x: bigint) {
                let y: bigint = 0n;
                for (let i: bigint = 0n; this.hp(); i++) {
                  y = y + 1n;
                }
                assert(x > y);
              }
            """);
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        Exception e = assertThrows(Exception.class, () -> Validate.run(c),
            "Validate used to refuse this shape before Typecheck saw it");
        assertTrue(
            e.getMessage().contains("for-loop condition must be a comparison against a compile-time constant"),
            "unexpected validator message: " + e.getMessage()
        );
    }

    // --- controls ----------------------------------------------------------

    @Test
    void assertKeepsItsUnknownEscape() throws Exception {
        assertTrue(
            frontendErrors(ASSERT_UNKNOWN).isEmpty(),
            "assert()'s <unknown> escape is shared by all seven tiers — deleting it "
                + "would create a divergence, not close one"
        );
    }

    @Test
    void ordinaryBooleanConditionsAreUnaffected() throws Exception {
        for (String src : List.of(IF_BOOLEAN, TERNARY_BOOLEAN, FOR_BOUNDED)) {
            assertTrue(frontendErrors(src).isEmpty(),
                "a legal boolean condition was rejected");
        }
    }
}
