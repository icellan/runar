package runar.lang.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class OpcodeConcernsTest {

    @Test
    void codeSeparatorPresentEmitsInfo() {
        // OP_NOP OP_CODESEPARATOR OP_NOP
        ScriptParser.Parsed p = ScriptParser.parse("61ab61");
        List<Finding> findings = OpcodeConcerns.analyze(p.opcodes, 3);
        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("info", f.severity);
        assertEquals("CODESEPARATOR_PRESENT", f.code);
        assertEquals("OP_CODESEPARATOR", f.opcode);
        assertEquals(Integer.valueOf(1), f.offset);
    }

    @Test
    void largeScriptEmitsInfoOver500k() {
        // Synthetic >500_000-byte script of OP_NOPs.
        int nOps = 500_001;
        // Build OpStep list directly (parsing a 1MB hex string is wasteful here).
        java.util.List<OpStep> ops = new java.util.ArrayList<>(nOps);
        for (int i = 0; i < nOps; i++) {
            ops.add(OpStep.op(i, Opcodes.OP_NOP, "OP_NOP", 1));
        }
        List<Finding> findings = OpcodeConcerns.analyze(ops, nOps);
        // 1 LARGE_SCRIPT finding; no CODESEPARATOR.
        long large = findings.stream().filter(f -> "LARGE_SCRIPT".equals(f.code)).count();
        assertEquals(1, large);
        Finding f = findings.stream()
            .filter(x -> "LARGE_SCRIPT".equals(x.code)).findFirst().orElseThrow();
        // 500001 / 1024 ≈ 488.2822... toFixed(1) → "488.3"
        assertTrue(f.message.contains("488.3 KB"), "got: " + f.message);
        assertTrue(f.message.contains("500001 bytes"));
    }

    @Test
    void largeScriptFormatToFixed1RoundsHalfToEven() {
        // 1328100/1024 = 1296.97265625 → toFixed(1) = "1297.0"
        assertEquals("1297.0", OpcodeConcerns.jsToFixed1(1328100.0 / 1024.0));
        // 1024 → 1.0
        assertEquals("1.0", OpcodeConcerns.jsToFixed1(1.0));
        // 1500/1024 → 1.46484... → "1.5"
        assertEquals("1.5", OpcodeConcerns.jsToFixed1(1500.0 / 1024.0));
        // Exact .5 rounds half-to-even: 0.5 → 0.5 (banker's keeps .0 for 0.5? No,
        // 0.5 → tenths digit 5: 5 × 10 = 5.0, rint(5.0) → 5, so "0.5". OK.
        assertEquals("0.5", OpcodeConcerns.jsToFixed1(0.5));
    }
}
