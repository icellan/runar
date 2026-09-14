package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Three branch-merge defects fixed 2026-08-06, pinned to the seven-tier script.
 * Port of the TypeScript reference test
 * {@code packages/runar-compiler/src/__tests__/branch-merge-k1-and-dead-arm.test.ts}.
 *
 * <p>All three reproduced in ALL SEVEN TIERS, and all are the PALMER-1 family
 * ("one stack carrier asked to hold N live values") at the k=1 / k=2 arities the
 * 2026-08-05 branch-merged-locals fix did not cover:
 *
 * <ol>
 *   <li>FUND SAFETY, silent, fold-ON only. An {@code if} whose condition folds
 *       to a compile-time constant, whose STATICALLY DEAD arm rebinds exactly
 *       TWO locals both read after the branch, resolved every post-branch
 *       operand to the WRONG stack slot. Wrong in both directions: with
 *       {@code s = -60267} the source REJECTS and the deployed script ACCEPTED
 *       (a covenant guard bypassed); with {@code s = 1000} the source ACCEPTS
 *       and the deployed script REJECTED (an unspendable UTXO). Every tier
 *       emitted the same wrong script, so cross-tier agreement held perfectly
 *       while all seven were wrong together.</li>
 *   <li>A single local rebound FROM ITSELF in BOTH arms ({@code m0 = m0 + 1n} /
 *       {@code m0 = m0 - 1n}) was REJECTED with "value not found on stack", in
 *       both fold modes, though the same shape compiles at k=2 and without an
 *       {@code else}.</li>
 *   <li>The same k=1 merge under ANY compile-time-constant condition,
 *       fold-ON.</li>
 * </ol>
 *
 * <p>Fixes: {@link ConstantFold} no longer blanks a statically-dead arm (that
 * erased the {@code __merge$<i>} result block both arms carry, so ONE stack slot
 * was registered for K physical results), and {@link StackLower}'s
 * {@code the multi-result branch node} adopts the slot both arms rebound in place at
 * k=1.
 *
 * <p>The hexes are the SEVEN-TIER agreed output. Every tier pins the same
 * strings, which is what makes this a parity gate: a tier that lowers the fix
 * differently fails its own test.
 */
class BranchMergeDeadArmK1Test {

    /** k=2 locals rebound by a STATICALLY DEAD arm, both read after the branch. */
    private static final String DEAD_ARM_K2 =
        """
        import { SmartContract, assert } from 'runar-lang';

        class C extends SmartContract {
          readonly s: bigint;

          constructor(s: bigint) { super(s); this.s = s; }

          public m(p: bigint): void {
            let a: bigint = this.s;
            let b: bigint = -78n;
            if (false) {
              a = 1n;
              b = p;
            }
            assert(b <= a);
          }
        }""";

    /** One local rebound FROM ITSELF in both arms, read after the branch. */
    private static final String SELF_READ_BOTH_ARMS =
        """
        import { SmartContract, assert } from 'runar-lang';

        class C extends SmartContract {
          readonly a: bigint;

          constructor(a: bigint) { super(a); this.a = a; }

          public m(p: bigint): void {
            assert(this.a > -1000000n);
            let m0: bigint = 1n;
            if (p > 0n) {
              m0 = (m0 + 1n);
            } else {
              m0 = (m0 - 1n);
            }
            assert(m0 > -1000000n);
          }
        }""";

    /** The same k=1 merge under a compile-time-constant condition. */
    private static final String CONST_CONDITION_K1 =
        """
        import { SmartContract, assert } from 'runar-lang';

        class C extends SmartContract {
          readonly a: bigint;

          constructor(a: bigint) { super(a); this.a = a; }

          public m(p: bigint): void {
            assert(this.a > -1000000n);
            let m0: bigint = 1n;
            if (true) {
              m0 = 2n;
            } else {
              m0 = 3n;
            }
            assert(m0 > -1000000n);
          }
        }""";

    private record Case(String label, String source, boolean disableConstantFolding, String want) {}

    private static final List<Case> CASES = List.of(
        new Case("dead-arm-k2/fold-on", DEAD_ARM_K2, false,
            "00014e01ce006351547a6e7b757b7567527978557a7568527a75537a75527a7c7ba177"),
        new Case("dead-arm-k2/fold-off", DEAD_ARM_K2, true,
            "00014e8f006351537a6e7b757b75676e547a7568527a75527a757ca1"),
        new Case("self-read-both-arms/fold-on", SELF_READ_BOTH_ARMS, false,
            "000340420f0340428f7b7ca069517b00a06351787c9376776751787c94767768517a750340420f0340428f7b7ca07777"),
        new Case("self-read-both-arms/fold-off", SELF_READ_BOTH_ARMS, true,
            "000340420f8fa069517c00a06351787c9376776751787c94767768517a750340420f8fa0"),
        new Case("const-condition-k1/fold-on", CONST_CONDITION_K1, false,
            "000340420f0340428f7b7ca0695151635276776753767768517a750340420f0340428f7b7ca0777777"),
        new Case("const-condition-k1/fold-off", CONST_CONDITION_K1, true,
            "000340420f8fa0695151635276776753767768517a750340420f8fa077"));

    @Test
    void sevenTierScript() throws Exception {
        for (Case tc : CASES) {
            String got = PipelineTestSupport.hex(tc.source(), "C.runar.ts", tc.disableConstantFolding());
            assertEquals(tc.want(), got,
                tc.label() + ": script hex diverged from the seven-tier agreed output");
        }
    }

    /**
     * A constant condition must not be treated differently from a runtime one, at any arity.
     * Before the fix, only the k=2 dead-arm form broke, and only under folding — which is why
     * the fold-OFF parity fuzzers were blind to it.
     */
    @Test
    void constAndRuntimeConditionsAgree() throws Exception {
        for (String cond : List.of("if (false) {", "if (true) {", "if (p > 0n) {")) {
            for (boolean disable : List.of(false, true)) {
                String source = DEAD_ARM_K2.replace("if (false) {", cond);
                assertNotNull(PipelineTestSupport.hex(source, "C.runar.ts", disable), cond);
            }
        }
    }

    /**
     * The k=1 self-read shape used to be rejected while its neighbours compiled. A compiler
     * that refuses a shape at one arity and accepts it at the next is reporting a hole in its
     * own merge machinery, not a language restriction — which is why this was fixed rather
     * than turned into a diagnostic.
     */
    @Test
    void k2SiblingAndNoElseSiblingStillCompile() throws Exception {
        String k2 = SELF_READ_BOTH_ARMS
            .replace("    let m0: bigint = 1n;", "    let m0: bigint = 1n;\n    let m1: bigint = 2n;")
            .replace("      m0 = (m0 + 1n);", "      m0 = (m0 + 1n);\n      m1 = (m1 + 1n);")
            .replace("      m0 = (m0 - 1n);", "      m0 = (m0 - 1n);\n      m1 = (m1 - 1n);")
            .replace("    assert(m0 > -1000000n);\n  }",
                     "    assert((m0 > -1000000n) && (m1 > -1000000n));\n  }");
        String noElse = SELF_READ_BOTH_ARMS
            .replace("    } else {\n      m0 = (m0 - 1n);\n    }", "    }");

        for (String source : List.of(k2, noElse)) {
            for (boolean disable : List.of(false, true)) {
                assertNotNull(PipelineTestSupport.hex(source, "C.runar.ts", disable));
            }
        }
    }
}
