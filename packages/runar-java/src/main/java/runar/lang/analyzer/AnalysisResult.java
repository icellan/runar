package runar.lang.analyzer;

import java.util.List;

/** Top-level analyzer output object per spec §3.1. */
public final class AnalysisResult {
    public final String script;
    public final int scriptSize;
    public final List<Finding> findings;
    public final List<ExecutionPath> paths;
    public final Summary summary;

    public AnalysisResult(String script, int scriptSize, List<Finding> findings,
                          List<ExecutionPath> paths, Summary summary) {
        this.script = script;
        this.scriptSize = scriptSize;
        this.findings = List.copyOf(findings);
        this.paths = List.copyOf(paths);
        this.summary = summary;
    }
}
