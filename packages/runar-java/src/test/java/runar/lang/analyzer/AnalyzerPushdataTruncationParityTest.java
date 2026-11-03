package runar.lang.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * F-236: pins two cross-tier divergences against the TS reference
 * analyzer ({@code packages/runar-testing/src/analyzer}), confirmed by
 * running {@code analyzeScript} directly against both inputs below.
 *
 * <p>What these tests PROVE: for a truncated OP_PUSHDATA1/2/4 header (the
 * opcode byte present, its length byte(s) missing because the script ends
 * right there), TS emits an {@code INEFFICIENT_PUSH} finding (dataLength 0
 * qualifies for every threshold) — Java must too. And when that same push
 * (truncated OR not) is fully covered by a {@code rawScriptSpans} entry,
 * the push op is collapsed into a synthetic {@code RAW_SPAN} step and NO
 * {@code INEFFICIENT_PUSH} finding should survive, because TS/Python run
 * the push-encoding check AFTER collapsing, never before.
 *
 * <p>What these tests do NOT prove: full byte-for-byte JSON-report parity
 * across every finding/offset/ordering combination (that's
 * conformance/analyzer's job) — only that these two specific divergences,
 * both confirmed against the TS reference, are closed in the Java tier.
 */
class AnalyzerPushdataTruncationParityTest {

    private static List<Finding> inefficientPushFindings(AnalysisResult r) {
        return r.findings.stream()
            .filter(f -> "INEFFICIENT_PUSH".equals(f.code))
            .toList();
    }

    @Test
    void truncatedPushdata1HeaderEmitsInefficientPush() {
        // Bare OP_PUSHDATA1 (0x4c), no length byte follows: the script ends
        // right after the opcode. TS: dataLength is stamped 0 on this
        // synthetic op, and INEFFICIENT_PUSH fires because 0 <= 75.
        AnalysisResult r = Analyzer.analyzeScript("4c");
        List<Finding> push = inefficientPushFindings(r);
        assertEquals(1, push.size(), "expected one INEFFICIENT_PUSH finding: " + r.findings);
        Finding f = push.get(0);
        assertEquals("info", f.severity);
        assertEquals(Integer.valueOf(0), f.offset);
        assertEquals("OP_PUSHDATA1", f.opcode);
        assertTrue(f.message.contains("0-byte data"), "got: " + f.message);
        assertTrue(f.message.contains("opcode 0x00"), "got: " + f.message);
    }

    @Test
    void truncatedPushdata2HeaderEmitsInefficientPush() {
        // OP_NOP, then OP_PUSHDATA2 with only 1 of its 2 length bytes present.
        AnalysisResult r = Analyzer.analyzeScript("614d00");
        List<Finding> push = inefficientPushFindings(r);
        assertEquals(1, push.size(), "expected one INEFFICIENT_PUSH finding: " + r.findings);
        Finding f = push.get(0);
        assertEquals(Integer.valueOf(1), f.offset);
        assertEquals("OP_PUSHDATA2", f.opcode);
        assertTrue(f.message.contains("0-byte data"), "got: " + f.message);
        assertTrue(f.message.contains("OP_PUSHDATA1 would be more efficient"), "got: " + f.message);
    }

    @Test
    void truncatedPushdata4HeaderEmitsInefficientPush() {
        // OP_PUSHDATA4 with only 3 of its 4 length bytes present.
        AnalysisResult r = Analyzer.analyzeScript("4e000000");
        List<Finding> push = inefficientPushFindings(r);
        assertEquals(1, push.size(), "expected one INEFFICIENT_PUSH finding: " + r.findings);
        Finding f = push.get(0);
        assertEquals(Integer.valueOf(0), f.offset);
        assertEquals("OP_PUSHDATA4", f.opcode);
        assertTrue(f.message.contains("OP_PUSHDATA2 would be more efficient"), "got: " + f.message);
    }

    @Test
    void inefficientPushInsideRawSpanEmitsNoFinding() {
        // OP_PUSHDATA1 len=5 + 5 data bytes (7 bytes total), entirely covered
        // by a raw_script span. TS runs the push-encoding check on the
        // COLLAPSED op list (just the synthetic RAW_SPAN step, no
        // pushEncoding) so it emits nothing for this push.
        AnalyzeOptions options = new AnalyzeOptions(
            List.of(new RawScriptSpan(0, 7, 0, 0)));
        AnalysisResult r = Analyzer.analyzeScript("4c050102030405", options);
        List<Finding> push = inefficientPushFindings(r);
        assertTrue(push.isEmpty(), "expected no INEFFICIENT_PUSH finding: " + push);
    }

    @Test
    void truncatedPushdata1HeaderInsideRawSpanEmitsNoFinding() {
        // Combines both divergences: a truncated OP_PUSHDATA1 header (which
        // now gets a parser-level INEFFICIENT_PUSH finding per the first
        // fix) that is also fully covered by a raw_script span. The span
        // collapse must still suppress the finding — its offset no longer
        // corresponds to a real push op in the collapsed list, only to the
        // synthetic RAW_SPAN step.
        AnalyzeOptions options = new AnalyzeOptions(
            List.of(new RawScriptSpan(0, 1, 0, 0)));
        AnalysisResult r = Analyzer.analyzeScript("4c", options);
        List<Finding> push = inefficientPushFindings(r);
        assertTrue(push.isEmpty(), "expected no INEFFICIENT_PUSH finding: " + push);
    }
}
