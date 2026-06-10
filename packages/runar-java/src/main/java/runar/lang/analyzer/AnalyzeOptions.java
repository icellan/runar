package runar.lang.analyzer;

import java.util.Collections;
import java.util.List;

/** Optional analyzer inputs per spec §2. */
public final class AnalyzeOptions {
    public final List<RawScriptSpan> rawScriptSpans;

    public AnalyzeOptions() {
        this.rawScriptSpans = Collections.emptyList();
    }

    public AnalyzeOptions(List<RawScriptSpan> rawScriptSpans) {
        this.rawScriptSpans = List.copyOf(rawScriptSpans);
    }
}
