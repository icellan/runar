package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

/**
 * N-079 — the inlined argument alias must survive into a branch arm.
 *
 * <p>Port of the TypeScript reference test
 * {@code packages/runar-compiler/src/__tests__/n079-inlined-param-alias-branch-arm.test.ts}.
 *
 * <p>{@code spec/semantics.md} §6.3 defines a private method as source-level
 * substitution at every call site. So this:
 *
 * <pre>
 *   private pay(v: bigint): void { ...uses v... }
 *   public  go(v: bigint) { this.pay(v * 2n); }
 * </pre>
 *
 * and the hand-substituted program ({@code const a = v * 2n;} then the body
 * with {@code a} in place of {@code v}) are the SAME program and must compile
 * to the same script. That is an oracle needing no reference tier.
 *
 * <p>The defect: {@code inlinePrivateMethodCall} pushes the caller's argument
 * refs onto the CURRENT lowering context ({@code pushParamAlias}) and then
 * lowers the private method's body into it. When that body contains an
 * {@code if} / {@code for} / ternary, the arm is built by {@code subContext()}
 * — a FRESH context that did not copy {@code paramAliasStack}. A read of the
 * private's parameter inside the arm therefore found no alias and fell through
 * to {@code load_param}, which resolved to the CALLER's same-named parameter
 * instead of the argument that was passed in.
 *
 * <p>The covenant's output amount became {@code v + 100} where the source says
 * {@code (v * 2) + 100} — a continuation-hash mismatch (UTXO unspendable) or a
 * wrong payment. Nobody refused; five of the seven tiers silently emitted a
 * different program. Measured on the pre-fix HEAD,
 * {@code --disable-constant-folding}:
 *
 * <pre>
 *                  go   rust  python  zig  ruby  java  ts
 *   hand-inlined   705   705    705   705   705   705  705
 *   via helper     705   705    703   703   703   703  703
 * </pre>
 *
 * <p>Go and Rust were right: Go's {@code subContext} already deep-copied the
 * alias stack, with a comment naming this exact hazard.
 *
 * <p>Fifth field of the same sub-context missed one at a time —
 * {@code scriptLevelCodeSeparator} (R-010), {@code renamedParams} (#130),
 * {@code privateMethods} (N-051), the three {@code MethodScope} fields (R-072),
 * now {@code paramAliasStack}. Same family as the NEW-014 / NEW-018
 * branch-lowering arm contract.
 *
 * <p>The (byte length, sha256-of-hex) pairs below are the SEVEN-TIER agreed
 * output; every tier pins the same table, which is what makes this a parity
 * gate. The scripts are ~700 B (a stateful covenant — the ANF-level inliner
 * only fires for a helper that emits outputs), so they are pinned by digest
 * rather than inline.
 */
class N079InlinedParamAliasBranchArmTest {

    private static final String PRELUDE =
        """
        import { StatefulSmartContract, assert } from "runar-lang";

        class C extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) { super(count); this.count = count; }

        """;

    /** The item's probe: a helper containing an {@code if}, called with {@code v * 2n}. */
    private static final String IF_ARM = PRELUDE +
        """
          private pay(v: bigint): void {
            let extra: bigint = 0n;
            if (v > 5n) {
              extra = v + 100n;
            } else {
              extra = v + 1n;
            }
            this.addOutput(extra, this.count);
          }

          public go(v: bigint) {
            this.count = this.count + 1n;
            this.pay(v * 2n);
            assert(v >= 0n);
          }
        }
        """;

    /** §6.3 control: the same program with the helper substituted by hand. */
    private static final String IF_ARM_MANUAL = PRELUDE +
        """
          public go(v: bigint) {
            this.count = this.count + 1n;
            const a: bigint = v * 2n;
            let extra: bigint = 0n;
            if (a > 5n) {
              extra = a + 100n;
            } else {
              extra = a + 1n;
            }
            this.addOutput(extra, this.count);
            assert(v >= 0n);
          }
        }
        """;

    /** N-051 oracle: differs from {@code IF_ARM} ONLY inside the then-arm. */
    private static final String IF_ARM_200 = PRELUDE +
        """
          private pay(v: bigint): void {
            let extra: bigint = 0n;
            if (v > 5n) {
              extra = v + 200n;
            } else {
              extra = v + 1n;
            }
            this.addOutput(extra, this.count);
          }

          public go(v: bigint) {
            this.count = this.count + 1n;
            this.pay(v * 2n);
            assert(v >= 0n);
          }
        }
        """;

    /** Same hazard through a ternary arm. */
    private static final String TERNARY_ARM = PRELUDE +
        """
          private pay(v: bigint): void {
            const extra: bigint = v > 5n ? v + 100n : v + 1n;
            this.addOutput(extra, this.count);
          }

          public go(v: bigint) {
            this.count = this.count + 1n;
            this.pay(v * 2n);
            assert(v >= 0n);
          }
        }
        """;

    private static final String TERNARY_ARM_MANUAL = PRELUDE +
        """
          public go(v: bigint) {
            this.count = this.count + 1n;
            const a: bigint = v * 2n;
            const extra: bigint = a > 5n ? a + 100n : a + 1n;
            this.addOutput(extra, this.count);
            assert(v >= 0n);
          }
        }
        """;

    /** Same hazard through a {@code for} body — {@code subContext()} builds that too. */
    private static final String LOOP_BODY = PRELUDE +
        """
          private pay(v: bigint): void {
            let acc: bigint = 0n;
            for (let i = 0; i < 3; i++) {
              acc = acc + v;
            }
            this.addOutput(acc, this.count);
          }

          public go(v: bigint) {
            this.count = this.count + 1n;
            this.pay(v * 2n);
            assert(v >= 0n);
          }
        }
        """;

    private static final String LOOP_BODY_MANUAL = PRELUDE +
        """
          public go(v: bigint) {
            this.count = this.count + 1n;
            const a: bigint = v * 2n;
            let acc: bigint = 0n;
            for (let i = 0; i < 3; i++) {
              acc = acc + a;
            }
            this.addOutput(acc, this.count);
            assert(v >= 0n);
          }
        }
        """;

    /** Control: a helper with NO nested block at all. Must be byte-unchanged. */
    private static final String NO_IF = PRELUDE +
        """
          private pay(v: bigint): void {
            const extra: bigint = v + 100n;
            this.addOutput(extra, this.count);
          }

          public go(v: bigint) {
            this.count = this.count + 1n;
            this.pay(v * 2n);
            assert(v >= 0n);
          }
        }
        """;

    /**
     * Control: the parameter is read at STATEMENT level inside the helper, and
     * the {@code if} in the helper does not read it. Must be byte-unchanged.
     */
    private static final String STMT_LEVEL = PRELUDE +
        """
          private pay(v: bigint): void {
            const extra: bigint = v + 100n;
            let bump: bigint = 0n;
            if (this.count > 5n) {
              bump = 1n;
            } else {
              bump = 2n;
            }
            this.addOutput(extra + bump, this.count);
          }

          public go(v: bigint) {
            this.count = this.count + 1n;
            this.pay(v * 2n);
            assert(v >= 0n);
          }
        }
        """;

    /**
     * Control: the argument IS the caller's own parameter ({@code this.pay(v)}),
     * so caller-param and argument coincide and the WRONG lowering computed the
     * right VALUE. It was still a different script — 701 B where Go/Rust emitted
     * 703 — because the arm re-issued {@code load_param} instead of reading the
     * alias slot.
     */
    private static final String PASSTHROUGH = PRELUDE +
        """
          private pay(v: bigint): void {
            let extra: bigint = 0n;
            if (v > 5n) {
              extra = v + 100n;
            } else {
              extra = v + 1n;
            }
            this.addOutput(extra, this.count);
          }

          public go(v: bigint) {
            this.count = this.count + 1n;
            this.pay(v);
            assert(v >= 0n);
          }
        }
        """;

    /** {label, source, byte length, sha256 of the lowercase script hex}. */
    private static final Object[][] SEVEN_TIER = {
        {"if-arm", IF_ARM, 704,
            "0bbd49f182e77dbc5483e96f58f8a54e033741f89cba7e0c231f89d8a91c9d2e"},
        {"if-arm-manual", IF_ARM_MANUAL, 704,
            "0bbd49f182e77dbc5483e96f58f8a54e033741f89cba7e0c231f89d8a91c9d2e"},
        {"if-arm-200", IF_ARM_200, 705,
            "a0c90541131862a8f5cdf769992c8f2026137194f50cc1e00e1a5c293d01435b"},
        {"ternary-arm", TERNARY_ARM, 691,
            "f6b2ae0526262ccee7adc71d1291bb8e0ae193de42c1a4e3936b782da95e3caf"},
        {"ternary-arm-manual", TERNARY_ARM_MANUAL, 691,
            "f6b2ae0526262ccee7adc71d1291bb8e0ae193de42c1a4e3936b782da95e3caf"},
        {"loop-body", LOOP_BODY, 698,
            "3692231cef9275b5a87f1f9f9b268f5a39cc3c4f37fe6354a1b57b2e8d356d55"},
        {"loop-body-manual", LOOP_BODY_MANUAL, 698,
            "3692231cef9275b5a87f1f9f9b268f5a39cc3c4f37fe6354a1b57b2e8d356d55"},
        {"no-if", NO_IF, 683,
            "2807bc651b0cfac58c0a0835f42b39cf46ce28d1e64d1ba7421279ccfe6680ed"},
        {"stmt-level", STMT_LEVEL, 700,
            "99a4048c2311be65c0b463a5dbf666f970c8f0f70878664429d547d3b36adf37"},
        {"passthrough", PASSTHROUGH, 702,
            "b0a101dddb8547a0779029930b04856140ee40c7066d793257b6b42ae05fcb8f"},
    };

    private static String hex(String source, boolean disableConstantFolding) throws Exception {
        return PipelineTestSupport.hex(source, "C.runar.ts", disableConstantFolding)
            .toLowerCase(java.util.Locale.ROOT);
    }

    private static String digest(String scriptHex) throws Exception {
        byte[] sum = MessageDigest.getInstance("SHA-256")
            .digest(scriptHex.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(sum.length * 2);
        for (byte b : sum) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Test
    void sevenTierScriptForInlinedParamAlias() throws Exception {
        for (Object[] tc : SEVEN_TIER) {
            String label = (String) tc[0];
            String source = (String) tc[1];
            int wantLen = (Integer) tc[2];
            String wantSha = (String) tc[3];
            for (boolean disable : new boolean[] {true, false}) {
                String got = hex(source, disable);
                assertEquals(
                    wantLen,
                    got.length() / 2,
                    label + " (disableConstantFolding=" + disable
                        + "): script length diverged from the seven-tier agreed output");
                assertEquals(
                    wantSha,
                    digest(got),
                    label + " (disableConstantFolding=" + disable
                        + "): script bytes diverged from the seven-tier agreed output");
            }
        }
    }

    /**
     * {@code spec/semantics.md} §6.3: inlining IS substitution, so the helper
     * form and the hand-substituted program are the same program.
     */
    @Test
    void helperMatchesManualInline() throws Exception {
        String[][] cases = {
            {"if", IF_ARM, IF_ARM_MANUAL},
            {"ternary", TERNARY_ARM, TERNARY_ARM_MANUAL},
            {"for", LOOP_BODY, LOOP_BODY_MANUAL},
        };
        for (String[] tc : cases) {
            for (boolean disable : new boolean[] {true, false}) {
                assertEquals(
                    hex(tc[2], disable),
                    hex(tc[1], disable),
                    "helper with a nested " + tc[0]
                        + " diverged from the hand-inlined source (disableConstantFolding="
                        + disable + ")");
            }
        }
    }

    /**
     * The N-051 oracle, consulting no reference tier: two helper bodies that
     * differ ONLY inside the arm must not compile to the same script.
     */
    @Test
    void armReadsTheArgument() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            assertNotEquals(
                hex(IF_ARM, disable),
                hex(IF_ARM_200, disable),
                "two helper bodies differing only inside the arm compiled to the same "
                    + "script (disableConstantFolding=" + disable + ")");
        }
    }
}
