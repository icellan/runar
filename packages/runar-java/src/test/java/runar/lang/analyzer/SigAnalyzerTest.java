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

    // F-234: OP_2DROP pops the CHECKSIG result as surely as OP_DROP does, so
    // `OP_CHECKSIG OP_2DROP OP_1` used to verify clean. Proves the immediate
    // OP_2DROP form is flagged with the spec §5.1 message and that OP_NIP (which
    // removes the item BELOW the result) is not. Does not prove that longer
    // discard sequences (OP_SWAP OP_NIP, OP_TOALTSTACK, ...) are caught: the
    // rule only looks at the next opcode.
    @Test
    void checksigDroppedBy2DropDetected() {
        String[][] cases = {
            {"0000ac6d51", "OP_CHECKSIG result is dropped by OP_2DROP — signature check has no effect", "2"},
            {"000000ae6d51", "OP_CHECKMULTISIG result is dropped by OP_2DROP — signature check has no effect", "3"},
        };
        for (String[] c : cases) {
            ScriptParser.Parsed p = ScriptParser.parse(c[0]);
            List<Finding> findings = SigAnalyzer.analyze(p.opcodes, List.of());
            assertEquals(1, findings.size(), c[0]);
            Finding f = findings.get(0);
            assertEquals("CHECKSIG_RESULT_DROPPED", f.code);
            assertEquals("warning", f.severity);
            assertEquals(c[1], f.message);
            assertEquals(Integer.valueOf(c[2]), f.offset);
        }
        // OP_0 OP_0 OP_CHECKSIG OP_NIP — the result survives on top; not flagged.
        ScriptParser.Parsed nip = ScriptParser.parse("0000ac77");
        assertTrue(SigAnalyzer.analyze(nip.opcodes, List.of()).isEmpty());
    }

    @Test
    void checksigVerifyNotFlagged() {
        // OP_CHECKSIGVERIFY OP_DROP — only OP_CHECKSIG / OP_CHECKMULTISIG flag.
        ScriptParser.Parsed p = ScriptParser.parse("ad75");
        List<Finding> findings = SigAnalyzer.analyze(p.opcodes, List.of());
        assertTrue(findings.isEmpty());
    }
}
