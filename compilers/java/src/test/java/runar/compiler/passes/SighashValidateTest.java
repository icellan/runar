package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Issue #123 (security core) — field-usage validation for {@code @sighash}
 * modes. One rejection test per unsound rule (port of sighash-validate.test.ts
 * + the e88f202c audit fixes). Default ALL|FORKID methods are never flagged.
 */
class SighashValidateTest {

    private static List<String> errorsOf(String src) throws Exception {
        return PipelineTestSupport.diagnostics(src, "X.runar.ts").errors();
    }

    private static List<String> warningsOf(String src) throws Exception {
        return PipelineTestSupport.diagnostics(src, "X.runar.ts").warnings();
    }

    private static boolean anyMatch(List<String> msgs, String needle) {
        return msgs.stream().anyMatch(m -> m.contains(needle));
    }

    // ---- Rule 1: ANYONECANPAY -------------------------------------------------

    private static String guard(String directive) {
        return "class Guard extends SmartContract {\n"
            + "  readonly expected: ByteString;\n"
            + "  constructor(expected: ByteString) { super(expected); this.expected = expected; }\n"
            + "  " + directive + "\n"
            + "  public spend(pre: SigHashPreimage): void {\n"
            + "    assert(checkPreimage(pre));\n"
            + "    assert(extractHashPrevouts(pre) === this.expected);\n"
            + "  }\n"
            + "}\n";
    }

    @Test
    void rejectsExtractHashPrevoutsUnderAnyonecanpay() throws Exception {
        List<String> errs = errorsOf(guard("/** @sighash ALL|ANYONECANPAY|FORKID */"));
        assertTrue(anyMatch(errs, "hashPrevouts") && anyMatch(errs, "zeroed under ANYONECANPAY"),
            errs.toString());
    }

    @Test
    void rejectsExtractPrevOutputScriptUnderAnyonecanpay() throws Exception {
        String src =
            "class Co extends StatefulSmartContract {\n"
            + "  readonly h0: ByteString;\n"
            + "  n: bigint;\n"
            + "  constructor(h0: ByteString, n: bigint) { super(h0, n); this.h0 = h0; this.n = n; }\n"
            + "  /** @sighash ALL|ANYONECANPAY|FORKID */\n"
            + "  public coSpend(): void {\n"
            + "    const s = extractPrevOutputScript(1n, this.h0);\n"
            + "    assert(len(s) > 0n);\n"
            + "  }\n"
            + "}\n";
        List<String> errs = errorsOf(src);
        assertTrue(anyMatch(errs, "companion input") || anyMatch(errs, "prevout script"), errs.toString());
    }

    @Test
    void acceptsExtractHashPrevoutsUnderAllDefault() {
        assertTrue(PipelineTestSupport.compiles(guard(""), "X.runar.ts"));
        assertTrue(PipelineTestSupport.compiles(guard("/** @sighash ALL|FORKID */"), "X.runar.ts"));
    }

    // ---- Rule 2/3: NONE -------------------------------------------------------

    @Test
    void rejectsStateContinuationUnderNone() throws Exception {
        String src =
            "class Counter extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  /** @sighash NONE|FORKID */\n"
            + "  public bump(): void { this.n = this.n + 1n; }\n"
            + "}\n";
        List<String> errs = errorsOf(src);
        assertTrue(anyMatch(errs, "NONE commits to NO outputs") || anyMatch(errs, "continuation"),
            errs.toString());
    }

    @Test
    void acceptsMutationUnderAllDefault() {
        String src =
            "class Counter extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  public bump(): void { this.n = this.n + 1n; }\n"
            + "}\n";
        assertTrue(PipelineTestSupport.compiles(src, "X.runar.ts"));
    }

    // ---- Rule 4: SINGLE -------------------------------------------------------

    // D25: the #123 (F1) refusal predated the F-024 `_newAmount` floor and
    // N-038; SINGLE hashes the whole same-index output, value included, so a
    // mutate-only SINGLE continuation is sound (and the default for a contract
    // whose continuation methods are all mutate-only).
    @Test
    void acceptsMutateOnlyContinuationUnderSingle() throws Exception {
        String src =
            "class Counter extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  /** @sighash SINGLE|FORKID */\n"
            + "  public bump(): void { this.n = this.n + 1n; }\n"
            + "}\n";
        List<String> errs = errorsOf(src);
        assertEquals(List.of(), errs);
        assertTrue(PipelineTestSupport.compiles(src, "X.runar.ts"));
    }

    @Test
    void acceptsExplicitSingleAddOutputUnderSingleWithWarning() throws Exception {
        String src =
            "class Pay extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  /** @sighash SINGLE|FORKID */\n"
            + "  public settle(): void { this.addOutput(1000n, this.n); }\n"
            + "}\n";
        assertTrue(PipelineTestSupport.compiles(src, "X.runar.ts"));
        List<String> warns = warningsOf(src);
        assertTrue(anyMatch(warns, "SINGLE commits ONLY to the output at this input")
            || anyMatch(warns, "carries the FULL protected value"), warns.toString());
    }

    @Test
    void rejectsMultiOutputContinuationUnderSingle() throws Exception {
        String src =
            "class Multi extends StatefulSmartContract {\n"
            + "  count: bigint;\n"
            + "  constructor(count: bigint) { super(count); this.count = count; }\n"
            + "  /** @sighash SINGLE|FORKID */\n"
            + "  public split(): void {\n"
            + "    this.addOutput(1000n, this.count);\n"
            + "    this.addOutput(2000n, this.count);\n"
            + "  }\n"
            + "}\n";
        List<String> errs = errorsOf(src);
        assertTrue(anyMatch(errs, "SINGLE commits ONLY to the output at this input"), errs.toString());
    }

    @Test
    void rejectsRequireOutputP2pkhUnderSingle() throws Exception {
        String src =
            "class Cov extends StatefulSmartContract {\n"
            + "  readonly bondPKH: ByteString;\n"
            + "  readonly bond: bigint;\n"
            + "  constructor(bondPKH: ByteString, bond: bigint) {\n"
            + "    super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond;\n"
            + "  }\n"
            + "  /** @sighash SINGLE|FORKID */\n"
            + "  public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }\n"
            + "}\n";
        List<String> errs = errorsOf(src);
        assertTrue(anyMatch(errs, "'requireOutputP2PKH' asserts an output at a fixed index")
            && anyMatch(errs, "SINGLE"), errs.toString());
    }

    @Test
    void acceptsMultiOutputMethodUnderAllDefault() {
        String src =
            "class Multi extends StatefulSmartContract {\n"
            + "  count: bigint;\n"
            + "  constructor(count: bigint) { super(count); this.count = count; }\n"
            + "  public split(): void {\n"
            + "    this.addOutput(1000n, this.count);\n"
            + "    this.addOutput(2000n, this.count);\n"
            + "  }\n"
            + "}\n";
        assertTrue(PipelineTestSupport.compiles(src, "X.runar.ts"));
    }

    // ---- F3: transitive walk covers the for-loop header -----------------------

    @Test
    void rejectsHashOutputsHiddenInForLoopConditionUnderNone() throws Exception {
        String src =
            "class C extends SmartContract {\n"
            + "  readonly expected: ByteString;\n"
            + "  constructor(expected: ByteString) { super(expected); this.expected = expected; }\n"
            + "  /** @sighash NONE|FORKID */\n"
            + "  public spend(pre: SigHashPreimage): void {\n"
            + "    for (let i = 0n; i < 3n && extractOutputHash(pre) === this.expected; i++) { assert(i < 2n); }\n"
            + "    assert(checkPreimage(pre));\n"
            + "  }\n"
            + "}\n";
        List<String> errs = errorsOf(src);
        assertTrue(anyMatch(errs, "hashOutputs") && anyMatch(errs, "zeroed under NONE"), errs.toString());
    }
}
