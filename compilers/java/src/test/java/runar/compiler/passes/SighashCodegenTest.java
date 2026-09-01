package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Issue #123 — mode-aware codegen: the declared sighash flag is threaded into
 * the OP_PUSH_TX binding blob + the preimage-type assert. Port of
 * sighash-codegen.test.ts. A SINGLE-safe body (explicit single addOutput) is
 * used for the SINGLE cases because a mutate-only SINGLE continuation is a
 * compile REJECT (F1).
 */
class SighashCodegenTest {

    private static String counterOut(String directive) {
        return "class Counter extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  " + directive + "\n"
            + "  public bump(): void { this.addOutput(1000n, this.n); }\n"
            + "}\n";
    }

    private static String fund(String directive) {
        return "class Fund extends StatefulSmartContract {\n"
            + "  raised: bigint;\n"
            + "  constructor(raised: bigint) { super(raised); this.raised = raised; }\n"
            + "  " + directive + "\n"
            + "  public pledge(amount: bigint): void { this.raised = this.raised + amount; }\n"
            + "}\n";
    }

    @Test
    void defaultIsByteIdenticalToExplicitAllForkid() throws Exception {
        String noDirective = PipelineTestSupport.hex(counterOut(""), "Counter.runar.ts");
        String explicitAll = PipelineTestSupport.hex(
            counterOut("/** @sighash ALL|FORKID */"), "Counter.runar.ts");
        assertEquals(noDirective, explicitAll);
    }

    @Test
    void singleForkidChangesTheScript() throws Exception {
        String dflt = PipelineTestSupport.hex(counterOut(""), "Counter.runar.ts");
        String single = PipelineTestSupport.hex(
            counterOut("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts");
        assertNotEquals(dflt, single);
        // The SINGLE|FORKID flag byte 0x43 is appended as the OP_PUSH_TX sighash
        // byte (OP_PUSHDATA(1) 0x43 = "0143").
        assertTrue(single.contains("0143"), "single script must contain 0143");
        // The default is still pinned to the 0x41 push.
        assertTrue(dflt.contains("0141"), "default script must contain 0141");
    }

    @Test
    void anyonecanpayChangesTheScriptToC1() throws Exception {
        String dflt = PipelineTestSupport.hex(fund(""), "Fund.runar.ts");
        String acp = PipelineTestSupport.hex(
            fund("/** @sighash ALL|ANYONECANPAY|FORKID */"), "Fund.runar.ts");
        assertNotEquals(dflt, acp);
        assertTrue(acp.contains("01c1"), "ANYONECANPAY script must contain 01c1");
        assertTrue(dflt.contains("0141"), "default script must contain 0141");
    }

    @Test
    void anfCheckPreimageCarriesTheDeclaredFlag() throws Exception {
        String anf = PipelineTestSupport.anfJson(
            counterOut("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts");
        // The check_preimage node carries the declared flag (0x43 = 67).
        assertTrue(anf.contains("\"sighashFlag\":67"), "ANF must carry sighashFlag 67: " + anf);
    }

    @Test
    void anfDefaultOmitsSighashFlag() throws Exception {
        String anf = PipelineTestSupport.anfJson(counterOut(""), "Counter.runar.ts");
        assertTrue(!anf.contains("sighashFlag"),
            "default ANF must omit sighashFlag (byte-identical to pinned): " + anf);
    }

    /**
     * Java parity with the TypeScript reference: the SINGLE-safe counter under
     * SINGLE|FORKID differs from the default (ALL|FORKID) at EXACTLY two byte
     * offsets — the OP_PUSH_TX binding flag byte (byte 393) and the
     * auto-injected preimage-type assert const (byte 439) — each 0x41 -> 0x43.
     * These are the exact positions measured from the TS compiler's scriptHex
     * (`compile(src, { disableConstantFolding: true })`), so a Java default that
     * already matches TS (cross-tier conformance) yields a byte-identical SINGLE.
     */
    @Test
    void singleDiffersFromDefaultAtExactlyTheTwoSighashBytes() throws Exception {
        String dflt = PipelineTestSupport.hex(counterOut(""), "Counter.runar.ts");
        String single = PipelineTestSupport.hex(
            counterOut("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts");
        assertEquals(dflt.length(), single.length());
        java.util.List<Integer> diffBytes = new java.util.ArrayList<>();
        for (int i = 0; i < dflt.length(); i += 2) {
            if (!dflt.regionMatches(i, single, i, 2)) {
                diffBytes.add(i / 2);
                assertEquals("41", dflt.substring(i, i + 2));
                assertEquals("43", single.substring(i, i + 2));
            }
        }
        assertEquals(java.util.List.of(393, 439), diffBytes,
            "SINGLE must change exactly the binding flag byte + the preimage-type assert const");
    }
}
