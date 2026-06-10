package runar.lang.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class SigAnalyzerTest {

    @Test
    void noSigCheckPerPathLackingCheckSig() {
        ExecutionPath p1 = new ExecutionPath(0, "linear (no branches)",
            List.of(), true, false, 0);
        ExecutionPath p2 = new ExecutionPath(1, "IF[true] at 0",
            List.of(true), true, true, 0);
        List<Finding> findings = SigAnalyzer.analyze(List.of(), List.of(p1, p2));
        // Only p1 lacks CHECKSIG → one finding.
        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("NO_SIG_CHECK", f.code);
        assertEquals("linear (no branches)", f.path);
    }

    @Test
    void checksigDroppedDetected() {
        // OP_CHECKSIG OP_DROP
        ScriptParser.Parsed p = ScriptParser.parse("ac75");
        List<Finding> findings = SigAnalyzer.analyze(p.opcodes, List.of());
        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("CHECKSIG_RESULT_DROPPED", f.code);
        assertEquals("OP_CHECKSIG", f.opcode);
        assertEquals(Integer.valueOf(0), f.offset);
        assertTrue(f.message.contains("dropped by OP_DROP"));
    }

    @Test
    void checksigVerifyNotFlagged() {
        // OP_CHECKSIGVERIFY OP_DROP — only OP_CHECKSIG / OP_CHECKMULTISIG flag.
        ScriptParser.Parsed p = ScriptParser.parse("ad75");
        List<Finding> findings = SigAnalyzer.analyze(p.opcodes, List.of());
        assertTrue(findings.isEmpty());
    }
}
