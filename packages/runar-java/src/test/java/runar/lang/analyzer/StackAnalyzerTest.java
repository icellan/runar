package runar.lang.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class StackAnalyzerTest {

    @Test
    void linearAnalysisTracksDepth() {
        // OP_1 OP_1 OP_ADD → starts at 0, ends at +1.
        ScriptParser.Parsed p = ScriptParser.parse("515193");
        StackAnalyzer.LinearResult r = StackAnalyzer.analyze(p.opcodes, 0);
        assertEquals(1, r.depthAtEnd);
        assertEquals(2, r.maxDepth);
        assertTrue(r.findings.isEmpty());
    }

    @Test
    void negativeDepthAllowedWithInitialZero() {
        // OP_DROP at depth 0 → no underflow finding emitted (spec §8.2 step 4).
        ScriptParser.Parsed p = ScriptParser.parse("75");
        StackAnalyzer.LinearResult r = StackAnalyzer.analyze(p.opcodes, 0);
        assertEquals(-1, r.depthAtEnd);
        assertTrue(r.findings.isEmpty());
    }

    @Test
    void underflowEmittedOnlyWhenInitialDepthPositive() {
        // OP_DROP + OP_DROP → with initialDepth=1, second OP_DROP underflows.
        ScriptParser.Parsed p = ScriptParser.parse("7575");
        StackAnalyzer.LinearResult r = StackAnalyzer.analyze(p.opcodes, 1);
        // First DROP: depth 1→0 (no flag since 1>=1). Second DROP at depth 0
        // requires 1 → underflow flagged.
        long underflow = r.findings.stream()
            .filter(f -> "STACK_UNDERFLOW".equals(f.code)).count();
        assertEquals(1, underflow);
    }

    @Test
    void unreachableAfterReturnEmitsFinding() {
        // OP_RETURN OP_DROP → unreachable opcode warning.
        ScriptParser.Parsed p = ScriptParser.parse("6a75");
        StackAnalyzer.LinearResult r = StackAnalyzer.analyze(p.opcodes, 0);
        assertEquals(1, r.findings.size());
        Finding f = r.findings.get(0);
        assertEquals("UNREACHABLE_AFTER_RETURN", f.code);
        assertEquals("OP_DROP", f.opcode);
    }
}
