package runar.lang.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Byte-identity gate: for each of the 8 canonical analyzer fixtures, the
 * Java analyzer's JSON output must equal the golden under
 * {@code conformance/analyzer/<fixture>/expected-analyzer-report.json}.
 *
 * <p>The tests are skipped when run outside the repo layout (e.g. when
 * the package is consumed as a published artifact). When skipped, the
 * cross-tier conformance driver remains the binding gate.
 */
class FixtureConformanceTest {

    static Stream<String> fixtures() {
        return Stream.of(
            "basic-p2pkh",
            "escrow",
            "stateful-counter",
            "auction",
            "covenant-vault",
            "ec-demo",
            "schnorr-zkp",
            "if-else"
        );
    }

    static boolean repoLayoutAvailable() {
        return Files.isDirectory(repoRoot().resolve("conformance/analyzer"));
    }

    private static Path repoRoot() {
        // tests run from packages/runar-java; the repo root is two levels up.
        Path cwd = Paths.get("").toAbsolutePath();
        Path candidate = cwd;
        for (int i = 0; i < 6; i++) {
            if (Files.isDirectory(candidate.resolve("conformance/analyzer"))) {
                return candidate;
            }
            Path parent = candidate.getParent();
            if (parent == null) break;
            candidate = parent;
        }
        return cwd;
    }

    @ParameterizedTest(name = "fixture {0}")
    @MethodSource("fixtures")
    @EnabledIf("repoLayoutAvailable")
    void analyzerMatchesGolden(String fixture) throws IOException {
        Path root = repoRoot();
        Path hexPath = root.resolve("conformance/tests/" + fixture + "/expected-script.hex");
        Path goldenPath = root.resolve("conformance/analyzer/" + fixture
            + "/expected-analyzer-report.json");
        assertTrue(Files.isReadable(hexPath), "hex missing: " + hexPath);
        assertTrue(Files.isReadable(goldenPath), "golden missing: " + goldenPath);

        String hex = Files.readString(hexPath, StandardCharsets.UTF_8).trim();
        String expected = Files.readString(goldenPath, StandardCharsets.UTF_8);
        String actual = Analyzer.analyzeScriptJson(hex);
        if (!expected.equals(actual)) {
            // Surface the first divergent line for debugging.
            String[] e = expected.split("\n", -1);
            String[] a = actual.split("\n", -1);
            int max = Math.max(e.length, a.length);
            for (int i = 0; i < max; i++) {
                String el = i < e.length ? e[i] : "<eof>";
                String al = i < a.length ? a[i] : "<eof>";
                if (!el.equals(al)) {
                    throw new AssertionError("fixture=" + fixture
                        + " first divergence at line " + (i + 1)
                        + "\n  expected: " + el
                        + "\n  actual:   " + al);
                }
            }
            throw new AssertionError("fixture=" + fixture
                + " differs but no line diverged (length mismatch)");
        }
        assertEquals(expected, actual);
    }
}
