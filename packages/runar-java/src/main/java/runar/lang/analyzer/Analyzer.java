package runar.lang.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Top-level entry point for the Bitcoin Script static analyzer (spec §11).
 *
 * <p>{@link #analyzeScript(String)} returns an {@link AnalysisResult}.
 * {@link #analyzeScriptJson(String)} convenience method renders the
 * result with {@link ReportJson} (byte-identical to the cross-tier
 * goldens at {@code conformance/analyzer/}).
 */
public final class Analyzer {
    private Analyzer() {}

    public static AnalysisResult analyzeScript(String hexScript) {
        return analyzeScript(hexScript, new AnalyzeOptions());
    }

    public static AnalysisResult analyzeScript(String hexScript, AnalyzeOptions options) {
        String normalized = normalize(hexScript);
        int scriptSizeBytes = normalized.length() / 2;

        // Empty input: spec §2.1.
        if (scriptSizeBytes == 0) {
            Finding terminal = new Finding(
                "error", "INVALID_TERMINAL_STACK",
                "Empty script — no opcodes to execute",
                null, null, null);
            Summary summary = new Summary(0, 0, 0, 0, 0, 0);
            return new AnalysisResult(
                "", 0, List.of(terminal), List.of(), summary);
        }

        ScriptParser.Parsed parsed = ScriptParser.parse(normalized);
        List<OpStep> ops = parsed.opcodes;
        List<Finding> parserFindings = parsed.findings;

        if (options.rawScriptSpans != null && !options.rawScriptSpans.isEmpty()) {
            ops = ScriptParser.collapseRawScriptSpans(ops, options.rawScriptSpans);
        }

        List<Finding> all = new ArrayList<>();
        // Step 1: path analysis.
        PathAnalyzer.PathResult pr = PathAnalyzer.analyze(ops);
        all.addAll(pr.findings);

        // Step 2: linear fallback when no paths produced and no unbalanced findings.
        if (pr.paths.isEmpty() && !pr.hasUnbalanced) {
            StackAnalyzer.LinearResult lr = StackAnalyzer.analyze(ops, 0);
            all.addAll(lr.findings);
        }

        // Step 3: sig hygiene.
        all.addAll(SigAnalyzer.analyze(ops, pr.paths));

        // Step 4: opcode concerns (LARGE_SCRIPT, CODESEPARATOR_PRESENT, INEFFICIENT_PUSH).
        all.addAll(OpcodeConcerns.analyze(ops, scriptSizeBytes));
        // INEFFICIENT_PUSH findings come from the parser; per spec §11
        // orchestration, opcode-concern findings are appended last. Place
        // the parser-emitted push findings inside that bucket so they sort
        // alongside the other opcode concerns.
        all.addAll(parserFindings);

        // Sort (stable) by (severityRank, offsetRank). Optional-offset findings
        // sort to the end within their severity bucket. Ties are broken by
        // original insertion order.
        sortFindings(all);

        // Build summary.
        int totalPaths = pr.paths.size();
        int reachable = 0;
        int withCheck = 0;
        int withoutCheck = 0;
        int maxStackDepth = 0;
        for (ExecutionPath p : pr.paths) {
            if (p.reachable) {
                reachable++;
                if (p.hasCheckSig) withCheck++; else withoutCheck++;
            }
            if (p.stackDepthAtEnd > maxStackDepth) maxStackDepth = p.stackDepthAtEnd;
        }
        Summary summary = new Summary(
            totalPaths, reachable, withCheck, withoutCheck, maxStackDepth, scriptSizeBytes);

        return new AnalysisResult(normalized, scriptSizeBytes, all, pr.paths, summary);
    }

    public static String analyzeScriptJson(String hexScript) {
        return ReportJson.render(analyzeScript(hexScript));
    }

    /**
     * Strip whitespace and lowercase. Spec §2: "Whitespace is permitted and
     * stripped; the canonical normalized form is lowercase-hex with no
     * whitespace."
     */
    private static String normalize(String hex) {
        StringBuilder sb = new StringBuilder(hex.length());
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (Character.isWhitespace(c)) continue;
            if (c >= 'A' && c <= 'F') c = (char) (c - 'A' + 'a');
            sb.append(c);
        }
        return sb.toString();
    }

    private static void sortFindings(List<Finding> findings) {
        // Tag with insertion order so the stable sort's "equal" handling
        // is explicit and obvious — though Collections.sort is already
        // stable in Java.
        for (int i = 0; i < findings.size(); i++) {
            findings.get(i).insertionOrder = i;
        }
        Comparator<Finding> cmp = (a, b) -> {
            int sa = Finding.severityRank(a.severity);
            int sb = Finding.severityRank(b.severity);
            if (sa != sb) return Integer.compare(sa, sb);
            int oa = (a.offset != null) ? a.offset : Integer.MAX_VALUE;
            int ob = (b.offset != null) ? b.offset : Integer.MAX_VALUE;
            return Integer.compare(oa, ob);
        };
        Collections.sort(findings, cmp);
    }
}
