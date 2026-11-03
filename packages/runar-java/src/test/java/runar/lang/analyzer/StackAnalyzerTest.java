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

    /**
     * F-131. The seven Chronicle opcodes the compiler emits, with the
     * (pops, pushes) the @bsv/sdk interpreter (Spend.ts) gives them.
     * Proves: each is named per spec §4.1 and modelled with its real stack
     * effect, in the lookup and in the observable report (underflow message,
     * stackDepthAtEnd, maxStackDepth). Does not prove runtime semantics (the
     * analyzer is static) and does not re-derive the arities from the interpreter.
     */
    @Test
    void chronicleOpcodesCarryRealNamesAndEffects() {
        Object[][] cases = {
            {"8d", "OP_2MUL", 1, 1},
            {"8e", "OP_2DIV", 1, 1},
            {"b3", "OP_SUBSTR", 3, 1},
            {"b4", "OP_LEFT", 2, 1},
            {"b5", "OP_RIGHT", 2, 1},
            {"b6", "OP_LSHIFTNUM", 2, 1},
            {"b7", "OP_RSHIFTNUM", 2, 1},
        };
        for (Object[] c : cases) {
            String b = (String) c[0];
            String name = (String) c[1];
            int pops = (Integer) c[2];
            int pushes = (Integer) c[3];

            OpStep op = ScriptParser.parse(b).opcodes.get(0);
            assertEquals(name, op.name, "0x" + b + " name");
            StackAnalyzer.Effect e = StackAnalyzer.effectFor(op);
            assertEquals(pops, e.pops, name + " pops");
            assertEquals(pushes, e.pushes, name + " pushes");

            // OP_DROP empties a stack of known depth 1, then the opcode needs `pops` items.
            StackAnalyzer.LinearResult lin =
                StackAnalyzer.analyze(ScriptParser.parse("75" + b).opcodes, 1);
            String want = name + " requires " + pops + " stack item(s) but only 0 available";
            assertTrue(lin.findings.stream().anyMatch(
                f -> "STACK_UNDERFLOW".equals(f.code) && want.equals(f.message)),
                name + ": missing underflow " + want);

            // `pops` pushes of OP_1 then the opcode leave exactly `pushes` items.
            AnalysisResult r = Analyzer.analyzeScript("51".repeat(pops) + b);
            assertEquals(pushes, r.paths.get(0).stackDepthAtEnd, name + " depth at end");
            assertEquals(pushes, r.summary.maxStackDepth, name + " maxStackDepth");
        }

        // A genuinely unknown byte keeps the OP_UNKNOWN name and (0, 0) effect.
        OpStep unknown = ScriptParser.parse("b8").opcodes.get(0);
        assertEquals("OP_UNKNOWN(0xb8)", unknown.name);
        assertEquals(0, StackAnalyzer.effectFor(unknown).pops);
        assertEquals(0, StackAnalyzer.effectFor(unknown).pushes);
    }
}
