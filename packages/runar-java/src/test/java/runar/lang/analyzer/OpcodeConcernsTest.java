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
    void largeScriptFormatToFixed1MatchesJsNonTieCases() {
        // None of these land on an exact tie at the tenths digit, so
        // round-half-up and round-half-to-even agree on all of them —
        // kept as a non-tie regression check alongside the tie case below.
        // 1328100/1024 = 1296.97265625 → toFixed(1) = "1297.0"
        assertEquals("1297.0", OpcodeConcerns.jsToFixed1(1328100.0 / 1024.0));
        // 1024 → 1.0
        assertEquals("1.0", OpcodeConcerns.jsToFixed1(1.0));
        // 1500/1024 → 1.46484... → "1.5"
        assertEquals("1.5", OpcodeConcerns.jsToFixed1(1500.0 / 1024.0));
        // 0.5 × 10 = 5.0 exactly (already an integer — no rounding decision).
        assertEquals("0.5", OpcodeConcerns.jsToFixed1(0.5));
    }

    @Test
    void largeScriptFormatToFixed1BreaksTiesLikeJsNotHalfToEven() {
        // 500992/1024 = 489.25 exactly (1024 is a power of two, so the
        // division has no floating-point error). Scaled by 10 that is
        // 4892.5 — an exact tie at the tenths digit. JS
        // Number.prototype.toFixed(1) does NOT use round-half-to-even: per
        // spec it picks the integer n for which n/10 - x is closest to
        // zero, and on a tie picks the LARGER n. Verified live:
        //   node -e "console.log((500992/1024).toFixed(1))" -> "489.3"
        // Math.rint (round-half-to-even) rounds 4892.5 down to 4892
        // because 4892 is already even, producing the wrong "489.2".
        assertEquals("489.3", OpcodeConcerns.jsToFixed1(500992.0 / 1024.0));
    }

    @Test
    void largeScriptFormatToFixed1DoesNotMoveExistingAnalyzerGoldens() {
        // Pins the two LARGE_SCRIPT conformance goldens
        // (conformance/analyzer/{ec-demo,schnorr-zkp}/expected-analyzer-report.json)
        // so the tie-rounding fix above is proven not to move them — neither
        // size lands on an exact .5 tie at the tenths digit.
        assertEquals("1306.0", OpcodeConcerns.jsToFixed1(1337343.0 / 1024.0));
        assertEquals("856.7", OpcodeConcerns.jsToFixed1(877253.0 / 1024.0));
    }
}
