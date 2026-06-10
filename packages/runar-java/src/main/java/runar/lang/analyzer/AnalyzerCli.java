package runar.lang.analyzer;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Conformance CLI shim. Reads a hex script from the path in argv[0] and
 * writes the analyzer report JSON to stdout. Used by
 * {@code tools/analyzer-runner/java.sh}.
 */
public final class AnalyzerCli {
    private AnalyzerCli() {}

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            err().println("usage: AnalyzerCli <hex-file>");
            System.exit(2);
            return;
        }
        Path p = Path.of(args[0]);
        String hex = Files.readString(p, StandardCharsets.UTF_8).trim();
        String json = Analyzer.analyzeScriptJson(hex);
        // Use raw UTF-8 stdout to preserve em-dash bytes regardless of the
        // platform's default System.out encoding.
        out().write(json.getBytes(StandardCharsets.UTF_8));
        out().flush();
    }

    private static java.io.OutputStream out() {
        return System.out;
    }

    private static PrintStream err() {
        return System.err;
    }
}
