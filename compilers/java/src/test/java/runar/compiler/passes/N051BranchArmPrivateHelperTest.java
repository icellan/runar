package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

/**
 * N-051 — a private-helper call inside a BRANCH ARM must inline the callee.
 *
 * <p>Port of the TypeScript reference test
 * {@code packages/runar-compiler/src/__tests__/n051-branch-arm-private-helper.test.ts}.
 *
 * <p>{@code spec/semantics.md} §6.3 defines a private method as source-level
 * substitution at every call site, and its canonical example is a helper call
 * in EXPRESSION position:
 *
 * <pre>
 *   private square(x: bigint): bigint { return x * x; }
 *   public verify(n: bigint): void { assert(this.square(n) &lt; 100n); }
 *   // After inlining:
 *   public verify(n: bigint): void { assert(n * n &lt; 100n); }
 * </pre>
 *
 * <p>{@code spec/ir-format.md} §4.7 keeps {@code method_call} in the canonical
 * ANF ("Inlining happens in a later compiler phase"), so the substitution is
 * stack lowering's job — and stack lowering lowers an {@code if}'s arms in a
 * FRESH context.
 *
 * <p>Java was already correct: {@code StackLower.LoweringContext#subContext}
 * copies {@code privateMethods} into the arm context. Go, Rust and Python did
 * not, and each improvised a different answer for the same source:
 *
 * <pre>
 *   const v: bigint = p &gt; 0n ? this.bump(p) : 0n;   // bump(x) = x + 1n
 *
 *   ts / zig / ruby / java   7600a0638b6700776800a2         (correct)
 *   go                       7600a063006700776800a2         (silently wrong)
 *   python                   7600a063007c00776700776800a2   (silently wrong)
 *   rust                     rejected: "unknown function 'bump'"
 * </pre>
 *
 * <p>This test exists in Java to hold that line: the tier that was right must
 * fail loudly if it ever drifts.
 *
 * <p>The hexes are the SEVEN-TIER agreed output. Every tier pins the same
 * strings, which is what makes this a parity gate.
 */
class N051BranchArmPrivateHelperTest {

    private static final String PRELUDE =
        """
        import { SmartContract, assert } from 'runar-lang';

        class C extends SmartContract {
          readonly s: bigint;

          constructor(s: bigint) { super(s); this.s = s; }
        """;

    /** Helper called from a ternary arm. */
    private static final String TERNARY_ARM_PLUS_1 = PRELUDE +
        """
          private bump(x: bigint): bigint { return x + 1n; }

          public m(p: bigint): void {
            const v: bigint = p > 0n ? this.bump(p) : 0n;
            assert(v >= this.s);
          }
        }
        """;

    /** Same shape, different callee body — the body-independence probe. */
    private static final String TERNARY_ARM_PLUS_2 = PRELUDE +
        """
          private bump(x: bigint): bigint { return x + 2n; }

          public m(p: bigint): void {
            const v: bigint = p > 0n ? this.bump(p) : 0n;
            assert(v >= this.s);
          }
        }
        """;

    /** Control: the same program with the helper inlined by hand. */
    private static final String TERNARY_ARM_MANUAL_INLINE = PRELUDE +
        """
          public m(p: bigint): void {
            const v: bigint = p > 0n ? p + 1n : 0n;
            assert(v >= this.s);
          }
        }
        """;

    /** Helper called from an {@code if} STATEMENT arm. */
    private static final String IF_STATEMENT_ARM = PRELUDE +
        """
          private bump(x: bigint): bigint { return x + 1n; }

          public m(p: bigint): void {
            let v: bigint = 0n;
            if (p > 0n) {
              v = this.bump(p);
            } else {
              v = 0n;
            }
            assert(v >= this.s);
          }
        }
        """;

    /** Control: the same {@code if} with no helper call in either arm. */
    private static final String IF_STATEMENT_ARM_NO_HELPER = PRELUDE +
        """
          public m(p: bigint): void {
            let v: bigint = 0n;
            if (p > 0n) {
              v = p + 1n;
            } else {
              v = 0n;
            }
            assert(v >= this.s);
          }
        }
        """;

    /** Control: a helper call in ordinary statement position, outside any arm. */
    private static final String STATEMENT_POSITION = PRELUDE +
        """
          private bump(x: bigint): bigint { return x + 1n; }

          public m(p: bigint): void {
            const v: bigint = this.bump(p);
            assert(v >= this.s);
          }
        }
        """;

    private static String hex(String source, boolean disableConstantFolding) throws Exception {
        return PipelineTestSupport.hex(source, "C.runar.ts", disableConstantFolding);
    }

    @Test
    void sevenTierScriptForBranchArmPrivateHelper() throws Exception {
        String[][] cases = {
            {"ternary-arm/+1", TERNARY_ARM_PLUS_1, "7600a0638b6700776800a2"},
            {"ternary-arm/+2", TERNARY_ARM_PLUS_2, "7600a06352936700776800a2"},
            {"ternary-arm-manual-inline", TERNARY_ARM_MANUAL_INLINE, "7600a0638b6700776800a2"},
            {"if-statement-arm", IF_STATEMENT_ARM,
                "007800a0637c8b767676537a757777670076537a757768517a7500a2"},
            {"if-statement-arm-no-helper", IF_STATEMENT_ARM_NO_HELPER,
                "007800a0637c8b7677670076537a757768517a7500a2"},
            {"statement-position", STATEMENT_POSITION, "8b00a2"},
        };
        for (String[] tc : cases) {
            for (boolean disable : new boolean[] {true, false}) {
                assertEquals(
                    tc[2],
                    hex(tc[1], disable),
                    tc[0] + " (disableConstantFolding=" + disable
                        + "): script hex diverged from the seven-tier agreed output");
            }
        }
    }

    /**
     * {@code spec/semantics.md} §6.3: inlining IS substitution, so a helper call
     * in a ternary arm and the hand-substituted program are the same program.
     */
    @Test
    void ternaryArmMatchesManualInline() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            assertEquals(
                hex(TERNARY_ARM_MANUAL_INLINE, disable),
                hex(TERNARY_ARM_PLUS_1, disable),
                "helper-in-arm and hand-inlined source differ (disableConstantFolding="
                    + disable + ")");
        }
    }

    /**
     * The tier-independent oracle. No reference tier is consulted: a compiler
     * that emits the same bytes for {@code x + 1n} and {@code x + 2n} has
     * dropped the callee body, whatever its peers do.
     */
    @Test
    void calleeBodyReachesTheArm() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            assertNotEquals(
                hex(TERNARY_ARM_PLUS_1, disable),
                hex(TERNARY_ARM_PLUS_2, disable),
                "two different helper bodies compiled to the same script "
                    + "(disableConstantFolding=" + disable + ")");
        }
    }
}
