package runar.lang.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PathAnalyzerTest {

    @Test
    void linearPathHasNoBranches() {
        // OP_1 OP_DROP — no IFs.
        ScriptParser.Parsed p = ScriptParser.parse("5175");
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertEquals(1, r.paths.size());
        ExecutionPath path = r.paths.get(0);
        assertEquals(0, path.id);
        assertEquals("linear (no branches)", path.description);
        assertTrue(path.branchChoices.isEmpty());
        assertFalse(path.hasCheckSig);
    }

    @Test
    void singleIfElseProducesTwoPaths() {
        // OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
        ScriptParser.Parsed p = ScriptParser.parse("6351675268");
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertEquals(2, r.paths.size());
        // combo=0 → all false
        assertEquals(false, r.paths.get(0).branchChoices.get(0));
        // combo=1 → all true
        assertEquals(true, r.paths.get(1).branchChoices.get(0));
        assertTrue(r.paths.get(0).description.startsWith("IF[false] at "));
        assertTrue(r.paths.get(1).description.startsWith("IF[true] at "));
    }

    @Test
    void unbalancedIfEmits_UNBALANCED_IF_ENDIF() {
        // OP_IF OP_1 — no OP_ENDIF.
        ScriptParser.Parsed p = ScriptParser.parse("6351");
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertTrue(r.paths.isEmpty());
        assertTrue(r.hasUnbalanced);
        assertTrue(r.findings.stream().anyMatch(f -> "UNBALANCED_IF_ENDIF".equals(f.code)));
    }

    @Test
    void strayEndifEmitsUnbalanced() {
        // OP_ENDIF with no OP_IF
        ScriptParser.Parsed p = ScriptParser.parse("68");
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertTrue(r.hasUnbalanced);
        assertTrue(r.findings.stream().anyMatch(
            f -> "UNBALANCED_IF_ENDIF".equals(f.code)
                && "OP_ENDIF without matching OP_IF".equals(f.message)));
    }

    @Test
    void unconditionallySucceedsForEmptyPath() {
        // OP_1 — no verification opcode in a branchless script.
        ScriptParser.Parsed p = ScriptParser.parse("51");
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertTrue(r.findings.stream().anyMatch(f -> "UNCONDITIONALLY_SUCCEEDS".equals(f.code)));
    }

    @Test
    void inconsistentBranchDepthDetected() {
        // OP_IF OP_1 OP_ELSE OP_1 OP_1 OP_ENDIF  → THEN delta +1, ELSE delta +2.
        ScriptParser.Parsed p = ScriptParser.parse("635167515168");
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertTrue(r.findings.stream().anyMatch(
            f -> "INCONSISTENT_BRANCH_DEPTH".equals(f.code)
                && f.message.contains("THEN: 1, ELSE: 2")));
    }

    @Test
    void inconsistentBranchDepthNoElse() {
        // OP_IF OP_1 OP_ENDIF — body delta = +1 (push of OP_1), no OP_ELSE.
        ScriptParser.Parsed p = ScriptParser.parse("635168");
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertTrue(r.findings.stream().anyMatch(
            f -> "INCONSISTENT_BRANCH_DEPTH".equals(f.code)
                && f.message.contains("net stack delta 1")));
    }

    @Test
    void pathsTruncatedWhenManyBranches() {
        // Build a script with 9 IF/ENDIF blocks → 2^9 = 512 > 256, triggers truncation.
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 9; i++) sb.append("6368"); // OP_IF OP_ENDIF
        ScriptParser.Parsed p = ScriptParser.parse(sb.toString());
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertEquals(256, r.paths.size());
        assertTrue(r.findings.stream().anyMatch(
            f -> "PATHS_TRUNCATED".equals(f.code)
                && f.message.contains("9 branch points (2^9 = 512 paths)")));
    }

    @Test
    void pathsTruncatedForLargeBranches() {
        // Spec v1.2: 32 branches → 2^32 = 4_294_967_296 true paths,
        // PATHS_TRUNCATED is emitted with the exact-decimal message form.
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) sb.append("6368");
        ScriptParser.Parsed p = ScriptParser.parse(sb.toString());
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertEquals(256, r.paths.size());
        assertTrue(r.findings.stream().anyMatch(
            f -> "PATHS_TRUNCATED".equals(f.code)
                && f.message.contains("32 branch points (2^32 = 4294967296 paths)")));
    }

    @Test
    void pathsTruncatedRendersSymbolicallyForVeryLargeBranches() {
        // Spec v1.2: numBranches >= 53 renders "more than 2^53 paths" to
        // avoid overflowing the canonical TS reference's safe-integer range.
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 53; i++) sb.append("6368");
        ScriptParser.Parsed p = ScriptParser.parse(sb.toString());
        PathAnalyzer.PathResult r = PathAnalyzer.analyze(p.opcodes);
        assertEquals(256, r.paths.size());
        assertTrue(r.findings.stream().anyMatch(
            f -> "PATHS_TRUNCATED".equals(f.code)
                && f.message.contains("53 branch points (more than 2^53 paths)")));
    }
}
