package runar.lang.analyzer;

import java.util.List;

/**
 * Byte-exact JSON pretty-printer for {@link AnalysisResult} per spec §3.5:
 * <ul>
 *   <li>2-space indent, LF line endings, single trailing newline.</li>
 *   <li>Top / Finding / Path / Summary key orders as in §3.1 / §3.2 / §3.3 / §3.4.</li>
 *   <li>Optional Finding keys ({@code offset}, {@code opcode}, {@code path}) are
 *       omitted when {@code null}; never serialized as {@code null}.</li>
 *   <li>Solidus {@code /} is not escaped; non-ASCII (e.g. U+2014 em dash) is
 *       emitted verbatim as UTF-8.</li>
 * </ul>
 */
final class ReportJson {
    private ReportJson() {}

    static String render(AnalysisResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        // 1. script
        sb.append("  \"script\": ");
        writeString(sb, r.script);
        sb.append(",\n");
        // 2. scriptSize
        sb.append("  \"scriptSize\": ").append(r.scriptSize).append(",\n");
        // 3. findings
        sb.append("  \"findings\": ");
        renderFindings(sb, r.findings, 1);
        sb.append(",\n");
        // 4. paths
        sb.append("  \"paths\": ");
        renderPaths(sb, r.paths, 1);
        sb.append(",\n");
        // 5. summary
        sb.append("  \"summary\": ");
        renderSummary(sb, r.summary, 1);
        sb.append('\n');
        sb.append("}\n");
        return sb.toString();
    }

    private static void renderFindings(StringBuilder sb, List<Finding> findings, int depth) {
        if (findings.isEmpty()) {
            sb.append("[]");
            return;
        }
        String openIndent = indent(depth);
        String inner = indent(depth + 1);
        String inner2 = indent(depth + 2);
        sb.append("[\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append(inner).append("{\n");
            // severity
            sb.append(inner2).append("\"severity\": ");
            writeString(sb, f.severity);
            // The remaining keys depend on which optional fields are present.
            sb.append(",\n");
            sb.append(inner2).append("\"code\": ");
            writeString(sb, f.code);
            sb.append(",\n");
            sb.append(inner2).append("\"message\": ");
            writeString(sb, f.message);
            if (f.offset != null) {
                sb.append(",\n").append(inner2).append("\"offset\": ").append(f.offset);
            }
            if (f.opcode != null) {
                sb.append(",\n").append(inner2).append("\"opcode\": ");
                writeString(sb, f.opcode);
            }
            if (f.path != null) {
                sb.append(",\n").append(inner2).append("\"path\": ");
                writeString(sb, f.path);
            }
            sb.append('\n').append(inner).append('}');
            if (i + 1 < findings.size()) sb.append(',');
            sb.append('\n');
        }
        sb.append(openIndent).append(']');
    }

    private static void renderPaths(StringBuilder sb, List<ExecutionPath> paths, int depth) {
        if (paths.isEmpty()) {
            sb.append("[]");
            return;
        }
        String openIndent = indent(depth);
        String inner = indent(depth + 1);
        String inner2 = indent(depth + 2);
        sb.append("[\n");
        for (int i = 0; i < paths.size(); i++) {
            ExecutionPath p = paths.get(i);
            sb.append(inner).append("{\n");
            sb.append(inner2).append("\"id\": ").append(p.id).append(",\n");
            sb.append(inner2).append("\"description\": ");
            writeString(sb, p.description);
            sb.append(",\n");
            sb.append(inner2).append("\"branchChoices\": ");
            renderBooleanArray(sb, p.branchChoices, depth + 2);
            sb.append(",\n");
            sb.append(inner2).append("\"reachable\": ").append(p.reachable).append(",\n");
            sb.append(inner2).append("\"hasCheckSig\": ").append(p.hasCheckSig).append(",\n");
            sb.append(inner2).append("\"stackDepthAtEnd\": ").append(p.stackDepthAtEnd).append('\n');
            sb.append(inner).append('}');
            if (i + 1 < paths.size()) sb.append(',');
            sb.append('\n');
        }
        sb.append(openIndent).append(']');
    }

    private static void renderBooleanArray(StringBuilder sb, List<Boolean> arr, int depth) {
        if (arr.isEmpty()) {
            sb.append("[]");
            return;
        }
        String openIndent = indent(depth);
        String inner = indent(depth + 1);
        sb.append("[\n");
        for (int i = 0; i < arr.size(); i++) {
            sb.append(inner).append(arr.get(i) ? "true" : "false");
            if (i + 1 < arr.size()) sb.append(',');
            sb.append('\n');
        }
        sb.append(openIndent).append(']');
    }

    private static void renderSummary(StringBuilder sb, Summary s, int depth) {
        String openIndent = indent(depth);
        String inner = indent(depth + 1);
        sb.append("{\n");
        sb.append(inner).append("\"totalPaths\": ").append(s.totalPaths).append(",\n");
        sb.append(inner).append("\"reachablePaths\": ").append(s.reachablePaths).append(",\n");
        sb.append(inner).append("\"pathsWithCheckSig\": ").append(s.pathsWithCheckSig).append(",\n");
        sb.append(inner).append("\"pathsWithoutCheckSig\": ").append(s.pathsWithoutCheckSig).append(",\n");
        sb.append(inner).append("\"maxStackDepth\": ").append(s.maxStackDepth).append(",\n");
        sb.append(inner).append("\"scriptSizeBytes\": ").append(s.scriptSizeBytes).append('\n');
        sb.append(openIndent).append('}');
    }

    private static String indent(int depth) {
        StringBuilder sb = new StringBuilder(depth * 2);
        for (int i = 0; i < depth; i++) sb.append("  ");
        return sb.toString();
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
