package runar.lang.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AnalyzerTest {

    @Test
    void emptyScriptReturnsInvalidTerminalStack() {
        AnalysisResult r = Analyzer.analyzeScript("");
        assertEquals("", r.script);
        assertEquals(0, r.scriptSize);
        assertEquals(1, r.findings.size());
        Finding f = r.findings.get(0);
        assertEquals("error", f.severity);
        assertEquals("INVALID_TERMINAL_STACK", f.code);
        assertEquals("Empty script — no opcodes to execute", f.message);
        assertTrue(r.paths.isEmpty());
        assertEquals(0, r.summary.totalPaths);
        assertEquals(0, r.summary.scriptSizeBytes);
    }

    @Test
    void whitespaceAndUppercaseNormalized() {
        AnalysisResult r = Analyzer.analyzeScript(" 76 A9 88 AC ");
        assertEquals("76a988ac", r.script);
        assertEquals(4, r.scriptSize);
    }

    @Test
    void jsonRenderProducesTrailingNewline() {
        String json = Analyzer.analyzeScriptJson("00");
        assertTrue(json.endsWith("\n"));
        // Two-space indent.
        assertTrue(json.contains("  \"script\":"));
    }

    @Test
    void findingsSortedBySeverityThenOffset() {
        // Construct a script that produces:
        // - INCONSISTENT_BRANCH_DEPTH (warning, offset = ENDIF offset)
        // - CODESEPARATOR_PRESENT (info, offset = OP_CODESEPARATOR offset)
        // - NO_SIG_CHECK (warning, no offset → end of warning bucket)
        // OP_IF OP_1 OP_ENDIF OP_CODESEPARATOR
        AnalysisResult r = Analyzer.analyzeScript("635168ab");
        // First finding(s) should be warnings before infos.
        int firstInfoIdx = -1;
        int lastWarningIdx = -1;
        for (int i = 0; i < r.findings.size(); i++) {
            String sev = r.findings.get(i).severity;
            if ("warning".equals(sev)) lastWarningIdx = i;
            if ("info".equals(sev) && firstInfoIdx < 0) firstInfoIdx = i;
        }
        assertTrue(firstInfoIdx > lastWarningIdx,
            "warnings must precede infos in sorted findings: " + r.findings);
    }
}
