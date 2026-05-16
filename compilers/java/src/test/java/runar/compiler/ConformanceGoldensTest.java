package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * In-tree conformance-golden hex test (T-9 from
 * audits/cross-language-completeness-20260514.md §5.2).
 *
 * <p>Walks every fixture under {@code conformance/tests/}, locates the
 * {@code .runar.java} source path via {@code source.json}, compiles it
 * through the in-process Java {@link Cli} with
 * {@code --source <path> --hex --disable-constant-folding}, and asserts
 * the resulting hex matches {@code expected-script.hex} byte-for-byte.
 *
 * <p>Fixtures that carry a per-fixture {@code compilers} allowlist which
 * does not include {@code "java"} are skipped (these are scoped-out tiers
 * by project policy, e.g. Go-only EVM/STARK proof-system primitives).
 *
 * <p>Before this test, Java's golden + cross-tier byte parity was enforced
 * only via the external {@code conformance/runner} daemon; if that CI step
 * was skipped or broken, Java codegen regressions would escape
 * {@code gradle test}. This test plugs that gap by exercising the same
 * golden hex assertion in-process.
 */
class ConformanceGoldensTest {

    private static final Pattern COMPILERS_ARR =
        Pattern.compile("\"compilers\"\\s*:\\s*\\[([^\\]]*)]");
    private static final Pattern JAVA_SOURCE =
        Pattern.compile("\"\\.runar\\.java\"\\s*:\\s*\"([^\"]+)\"");

    @Test
    void allFixturesProduceByteIdenticalHex() throws IOException {
        Path conformanceDir = locateConformanceDir();
        List<Path> fixtures;
        try (Stream<Path> entries = Files.list(conformanceDir)) {
            fixtures = entries.filter(Files::isDirectory).sorted().toList();
        }
        assertTrue(!fixtures.isEmpty(), "no fixtures under " + conformanceDir);

        List<String> passed = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        List<String> missingSource = new ArrayList<>();
        List<String> failures = new ArrayList<>();

        for (Path fixtureDir : fixtures) {
            String name = fixtureDir.getFileName().toString();
            Path configPath = fixtureDir.resolve("source.json");
            if (!Files.exists(configPath)) {
                continue; // not a fixture
            }
            String configBody = Files.readString(configPath);

            // Per-fixture compilers allowlist: skip if java is excluded.
            if (!isJavaAllowed(configBody)) {
                skipped.add(name);
                continue;
            }

            // Locate the .runar.java source path relative to the fixture dir.
            Matcher srcMatch = JAVA_SOURCE.matcher(configBody);
            if (!srcMatch.find()) {
                missingSource.add(name);
                continue;
            }
            Path sourcePath = fixtureDir.resolve(srcMatch.group(1)).normalize();
            if (!Files.exists(sourcePath)) {
                missingSource.add(name + " (" + sourcePath + ")");
                continue;
            }

            Path expectedHexPath = fixtureDir.resolve("expected-script.hex");
            if (!Files.exists(expectedHexPath)) {
                // Fixture has no hex golden — skip silently.
                continue;
            }

            Result r = runCli("--source", sourcePath.toString(),
                              "--hex", "--disable-constant-folding");
            if (r.exit != 0) {
                failures.add(name + " — compiler exited " + r.exit
                             + ": " + (r.stderr.isBlank() ? r.stdout : r.stderr).trim());
                continue;
            }

            String actualHex = normalizeHex(r.stdout);
            String expectedHex = normalizeHex(Files.readString(expectedHexPath));

            if (!actualHex.equals(expectedHex)) {
                int firstDiff = firstDiffOffset(expectedHex, actualHex);
                failures.add(String.format(
                    "%s — script-mismatch; expected %d hex chars, actual %d; first diff at offset %d (byte %d)",
                    name, expectedHex.length(), actualHex.length(), firstDiff, firstDiff / 2));
            } else {
                passed.add(name);
            }
        }

        // Emit a concise report.
        StringBuilder report = new StringBuilder();
        report.append("\n=== Java conformance-goldens summary: ")
              .append(passed.size()).append(" pass / ")
              .append(failures.size()).append(" fail / ")
              .append(skipped.size()).append(" skipped (Java not in allowlist) / ")
              .append(missingSource.size()).append(" missing-source (of ")
              .append(fixtures.size()).append(" fixtures) ===\n");
        if (!failures.isEmpty()) {
            int limit = Math.min(5, failures.size());
            for (int i = 0; i < limit; i++) {
                report.append("  - ").append(failures.get(i)).append('\n');
            }
            if (failures.size() > limit) {
                report.append("  ... and ").append(failures.size() - limit)
                      .append(" more failures.\n");
            }
        }
        System.out.println(report);

        if (!failures.isEmpty()) {
            fail(failures.size() + " of " + fixtures.size()
                 + " fixtures failed conformance-goldens; see stdout for details");
        }
        // Sanity: ensure we actually exercised at least one fixture.
        assertTrue(!passed.isEmpty(),
                   "no fixtures passed — check that conformance/tests is populated");
    }

    /**
     * Returns {@code true} if the fixture's {@code source.json} either has no
     * {@code compilers} allowlist (i.e. all 7 tiers required) or the allowlist
     * explicitly includes {@code "java"}.
     */
    private static boolean isJavaAllowed(String configBody) {
        Matcher m = COMPILERS_ARR.matcher(configBody);
        if (!m.find()) return true; // no allowlist ⇒ all tiers required
        String body = m.group(1);
        // Parse the array entries as quoted strings.
        Matcher tier = Pattern.compile("\"([^\"]+)\"").matcher(body);
        while (tier.find()) {
            if ("java".equals(tier.group(1))) return true;
        }
        return false;
    }

    private static String normalizeHex(String s) {
        // Strip whitespace and lowercase, matching the canonicalization in the
        // peer in-tree golden tests (Ruby's conformance_goldens_test.rb,
        // Python's test_conformance_goldens.py).
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c)) continue;
            sb.append(Character.toLowerCase(c));
        }
        return sb.toString();
    }

    private static int firstDiffOffset(String expected, String actual) {
        int n = Math.min(expected.length(), actual.length());
        for (int i = 0; i < n; i++) {
            if (expected.charAt(i) != actual.charAt(i)) return i;
        }
        return n; // strings agree on the shorter prefix; mismatch is in length
    }

    private static Path locateConformanceDir() throws IOException {
        Path cwd = Paths.get("").toAbsolutePath();
        for (Path p = cwd; p != null; p = p.getParent()) {
            Path candidate = p.resolve("conformance").resolve("tests");
            if (Files.isDirectory(candidate)) return candidate;
        }
        throw new IOException("conformance/tests directory not found above " + cwd);
    }

    /**
     * In-process Java CLI invocation, capturing stdout / stderr. Mirrors the
     * helper in {@link CliTest}.
     */
    private static Result runCli(String... args) {
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream outPs = new PrintStream(stdout, true, StandardCharsets.UTF_8);
        PrintStream errPs = new PrintStream(stderr, true, StandardCharsets.UTF_8);
        int exit = new Cli(outPs, errPs).run(args);
        outPs.flush();
        errPs.flush();
        return new Result(
            exit,
            stdout.toString(StandardCharsets.UTF_8),
            stderr.toString(StandardCharsets.UTF_8)
        );
    }

    private record Result(int exit, String stdout, String stderr) {}
}
