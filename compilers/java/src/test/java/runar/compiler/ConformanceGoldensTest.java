package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import runar.compiler.canonical.Jcs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * In-tree conformance-golden hex test (T-9 from
 * audits/cross-language-completeness-20260514.md §5.2).
 *
 * <p>Walks every fixture under {@code conformance/tests/}, locates the
 * {@code .runar.java} source path via {@code source.json}, compiles it
 * through the in-process Java {@link Cli} with
 * {@code --source <path> --hex --disable-constant-folding} (and
 * {@code --emit-ir} for the canonical ANF comparison), and asserts the
 * resulting hex and IR match {@code expected-script.hex} /
 * {@code expected-ir.json} byte-for-byte.
 *
 * <p><strong>N-389 (R145, "named set, keep coverage"):</strong> a fixture
 * whose per-fixture {@code compilers} allowlist does not include
 * {@code "java"} is skipped ONLY when it is also named in
 * {@link #EXPECTED_NOT_JAVA_COMPILABLE}; every other fixture is compiled and
 * byte-checked even when its allowlist excludes java.
 *
 * <p>Before this test, Java's golden + cross-tier byte parity was enforced
 * only via the external {@code conformance/runner} daemon; if that CI step
 * was skipped or broken, Java codegen regressions would escape
 * {@code gradle test}. This test plugs that gap by exercising the same
 * golden assertions in-process.
 *
 * <p><strong>N-124:</strong> before this fix, classification had three ways
 * to report green on a fixture it never actually checked, the same shape
 * F-151/F-280/F-285/F-323 fixed in the other six tiers' own golden
 * harnesses:
 * <ul>
 *   <li>a fixture directory with no {@code source.json} silently vanished
 *       ({@code continue; // not a fixture}) — not counted as passed,
 *       failed, or skipped;
 *   <li>a fixture with no resolvable {@code .runar.java} source went into a
 *       {@code missingSource} bucket that was printed in the summary but
 *       never consulted by the final {@code fail(...)};
 *   <li>a missing {@code expected-script.hex} was "skipped silently"
 *       ({@code continue}, uncounted) rather than failed, and
 *       {@code expected-ir.json} was never read or compared at all — an IR
 *       codegen regression that still produced byte-identical hex (or that
 *       nothing exercised the hex path for) would pass this test
 *       unnoticed.
 * </ul>
 * {@link #classifyFixture} now treats all three as failures (missing
 * {@code source.json} and unresolvable source both report
 * {@code missing-source}; a missing IR or hex golden reports
 * {@code missing-golden-ir} / {@code missing-golden-hex}), and the IR
 * comparison is wired in alongside the existing hex comparison.
 */
class ConformanceGoldensTest {

    private static final Pattern COMPILERS_ARR =
        Pattern.compile("\"compilers\"\\s*:\\s*\\[([^\\]]*)]");
    private static final Pattern PARSER_SKIP_ARR =
        Pattern.compile("\"parserSkip\"\\s*:\\s*\\[([^\\]]*)]");
    private static final Pattern JAVA_SOURCE =
        Pattern.compile("\"\\.runar\\.java\"\\s*:\\s*\"([^\"]+)\"");

    /**
     * N-389 (R145): fixtures Java is EXPECTED to refuse. Java carries no
     * codegen for the Go-only EVM/STARK proof-system families: it refuses
     * with "Java tier carries partial port only" for BabyBear
     * (babybear, babybear-ext4, state-covenant), the sha256-Merkle family
     * (merkle-proof) and the BN254/Groth16 family (bn254-pairing). A fixture
     * is skipped only when it is named here AND its source.json allowlist
     * excludes java. Mirrors the Python harness's
     * EXPECTED_NOT_PYTHON_COMPILABLE (N-387); sorted.
     */
    private static final List<String> EXPECTED_NOT_JAVA_COMPILABLE = List.of(
        "babybear", "babybear-ext4", "bn254-pairing", "merkle-proof", "state-covenant");

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
        List<String> failures = new ArrayList<>();

        for (Path fixtureDir : fixtures) {
            FixtureOutcome outcome = classifyFixture(fixtureDir);
            switch (outcome.kind()) {
                case PASSED -> passed.add(outcome.name());
                case SKIPPED -> skipped.add(outcome.name());
                case FAILED -> failures.add(outcome.name() + " — " + outcome.detail());
            }
        }

        // Emit a concise report.
        StringBuilder report = new StringBuilder();
        report.append("\n=== Java conformance-goldens summary: ")
              .append(passed.size()).append(" pass / ")
              .append(failures.size()).append(" fail / ")
              .append(skipped.size()).append(" skipped (compilers allowlist or parserSkip excludes java) (of ")
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

        // N-389: the allowlist-skipped set must be exactly the named set
        // (any other skip must be a documented parserSkip), every named
        // entry must exist and really exclude java in its raw source.json,
        // and passed + skipped must account for every fixture.
        List<String> allowlistSkipped = new ArrayList<>();
        for (String name : skipped) {
            String body = Files.readString(conformanceDir.resolve(name).resolve("source.json"));
            if (EXPECTED_NOT_JAVA_COMPILABLE.contains(name)) {
                allowlistSkipped.add(name);
            } else {
                assertTrue(isJavaParserSkipped(body),
                    "fixture '" + name + "' was skipped but is neither named in "
                    + "EXPECTED_NOT_JAVA_COMPILABLE nor parserSkip-excluded");
            }
        }
        assertEquals(EXPECTED_NOT_JAVA_COMPILABLE, allowlistSkipped);
        for (String name : EXPECTED_NOT_JAVA_COMPILABLE) {
            Path configPath = conformanceDir.resolve(name).resolve("source.json");
            assertTrue(Files.exists(configPath),
                "EXPECTED_NOT_JAVA_COMPILABLE names unknown fixture '" + name + "'");
            assertTrue(excludesJavaRaw(Files.readString(configPath)),
                "'" + name + "' allowlist does not exclude java");
        }
        assertEquals(fixtures.size(), passed.size() + skipped.size());
    }

    private enum Kind { PASSED, SKIPPED, FAILED }

    private record FixtureOutcome(String name, Kind kind, String detail) {}

    /**
     * Classify (and, unless skipped/missing-source/missing-golden, compile
     * and compare) a single conformance fixture directory. Extracted from
     * {@link #allFixturesProduceByteIdenticalHex} so the classification
     * logic (N-124) is directly unit-testable against synthetic, throwaway
     * fixture directories ({@code @TempDir}), without depending on or
     * risking the real conformance corpus.
     */
    private static FixtureOutcome classifyFixture(Path fixtureDir) throws IOException {
        return classifyFixture(fixtureDir, EXPECTED_NOT_JAVA_COMPILABLE);
    }

    /**
     * N-389 (R145): a fixture is SKIPPED on the allowlist only when it is
     * named in {@code notCompilable} AND its {@code compilers} allowlist
     * excludes java. A named fixture whose allowlist does not exclude java is
     * a {@code stale-expected-not-compilable} failure. An unnamed fixture is
     * always compiled, even when its allowlist excludes java.
     */
    private static FixtureOutcome classifyFixture(Path fixtureDir, List<String> notCompilable)
            throws IOException {
        String name = fixtureDir.getFileName().toString();
        Path configPath = fixtureDir.resolve("source.json");
        if (!Files.exists(configPath)) {
            return new FixtureOutcome(name, Kind.FAILED,
                "missing-source: no source.json found for fixture '" + name + "'");
        }
        String configBody = Files.readString(configPath);

        // Per-fixture compilers allowlist (IR/hex parity scope): skip only
        // a NAMED fixture that excludes java (N-389).
        boolean javaAllowed = isJavaAllowed(configBody);
        if (notCompilable.contains(name)) {
            if (!javaAllowed) {
                return new FixtureOutcome(name, Kind.SKIPPED, null);
            }
            return new FixtureOutcome(name, Kind.FAILED,
                "stale-expected-not-compilable: fixture '" + name
                + "' is named in EXPECTED_NOT_JAVA_COMPILABLE but its source.json allowlist does not exclude java");
        }

        // Per-fixture parser opt-out (frontend-parity scope, a sibling of
        // the compilers allowlist — see CLAUDE.md's two invariants and
        // conformance/runner/runner.ts's parserSkip handling): a fixture
        // that documents ".runar.java" as unparseable on this surface (e.g.
        // fixed-array-index / fixed-array-write — FixedArray<T, N> is a
        // javac parse error, docs/formats/java.md) legitimately ships no
        // .runar.java source at all. This is a real, documented exclusion,
        // not a conformance gap N-124 should turn into a failure.
        if (isJavaParserSkipped(configBody)) {
            return new FixtureOutcome(name, Kind.SKIPPED, null);
        }

        // Locate the .runar.java source path relative to the fixture dir.
        Matcher srcMatch = JAVA_SOURCE.matcher(configBody);
        if (!srcMatch.find()) {
            return new FixtureOutcome(name, Kind.FAILED,
                "missing-source: no \".runar.java\" entry in source.json for fixture '" + name + "'");
        }
        Path sourcePath = fixtureDir.resolve(srcMatch.group(1)).normalize();
        if (!Files.exists(sourcePath)) {
            return new FixtureOutcome(name, Kind.FAILED,
                "missing-source: " + sourcePath + " does not exist");
        }

        Path expectedIrPath = fixtureDir.resolve("expected-ir.json");
        if (!Files.exists(expectedIrPath)) {
            return new FixtureOutcome(name, Kind.FAILED,
                "missing-golden-ir: expected-ir.json not found for fixture '" + name + "'");
        }
        Path expectedHexPath = fixtureDir.resolve("expected-script.hex");
        if (!Files.exists(expectedHexPath)) {
            return new FixtureOutcome(name, Kind.FAILED,
                "missing-golden-hex: expected-script.hex not found for fixture '" + name + "'");
        }

        Result irResult = runCli("--source", sourcePath.toString(),
                                  "--emit-ir", "--disable-constant-folding");
        if (irResult.exit != 0) {
            return new FixtureOutcome(name, Kind.FAILED, "compile-ir: compiler exited " + irResult.exit
                + ": " + (irResult.stderr.isBlank() ? irResult.stdout : irResult.stderr).trim());
        }

        String actualIrCanonical;
        String expectedIrCanonical;
        try {
            actualIrCanonical = canonicalIr(irResult.stdout);
            expectedIrCanonical = canonicalIr(Files.readString(expectedIrPath));
        } catch (RuntimeException e) {
            return new FixtureOutcome(name, Kind.FAILED, "canonicalize-ir: " + e.getMessage());
        }
        if (!actualIrCanonical.equals(expectedIrCanonical)) {
            return new FixtureOutcome(name, Kind.FAILED, String.format(
                "ir-mismatch; expected %d chars, actual %d chars",
                expectedIrCanonical.length(), actualIrCanonical.length()));
        }

        Result hexResult = runCli("--source", sourcePath.toString(),
                                   "--hex", "--disable-constant-folding");
        if (hexResult.exit != 0) {
            return new FixtureOutcome(name, Kind.FAILED, "compile-hex: compiler exited " + hexResult.exit
                + ": " + (hexResult.stderr.isBlank() ? hexResult.stdout : hexResult.stderr).trim());
        }

        String actualHex = normalizeHex(hexResult.stdout);
        String expectedHex = normalizeHex(Files.readString(expectedHexPath));
        if (!actualHex.equals(expectedHex)) {
            int firstDiff = firstDiffOffset(expectedHex, actualHex);
            return new FixtureOutcome(name, Kind.FAILED, String.format(
                "script-mismatch; expected %d hex chars, actual %d; first diff at offset %d (byte %d)",
                expectedHex.length(), actualHex.length(), firstDiff, firstDiff / 2));
        }

        return new FixtureOutcome(name, Kind.PASSED, null);
    }

    /**
     * Returns {@code true} if the fixture's {@code source.json} either has no
     * {@code compilers} allowlist (i.e. all 7 tiers required) or the allowlist
     * explicitly includes {@code "java"}.
     */
    private static boolean isJavaAllowed(String configBody) {
        Object cfg = MiniJson.parse(configBody);
        if (!(cfg instanceof Map<?, ?> map) || !map.containsKey("compilers")) {
            return true; // no allowlist ⇒ all tiers required
        }
        // N-389: fail closed. A `compilers` value that is not a list of
        // strings used to be treated as "no allowlist", silently admitting
        // the fixture.
        Object list = map.get("compilers");
        if (!(list instanceof List<?> entries) || !entries.stream().allMatch(e -> e instanceof String)) {
            throw new IllegalStateException(
                "source.json 'compilers' must be a list of strings, got " + list);
        }
        return entries.contains("java");
    }

    /**
     * Independent (raw regex) check that the allowlist excludes java.
     * Deliberately does not go through {@link #isJavaAllowed}.
     */
    private static boolean excludesJavaRaw(String configBody) {
        Matcher m = COMPILERS_ARR.matcher(configBody);
        if (!m.find()) return false;
        Matcher tier = Pattern.compile("\"([^\"]+)\"").matcher(m.group(1));
        while (tier.find()) {
            if ("java".equals(tier.group(1))) return false;
        }
        return true;
    }

    /**
     * Returns {@code true} if the fixture's {@code source.json} lists
     * {@code ".runar.java"} in a {@code parserSkip} array — the documented
     * frontend-parity opt-out (mirrors
     * {@code conformance/runner/runner.ts}'s {@code parserSkip} handling).
     */
    private static boolean isJavaParserSkipped(String configBody) {
        Matcher m = PARSER_SKIP_ARR.matcher(configBody);
        if (!m.find()) return false; // no parserSkip ⇒ not skipped
        String body = m.group(1);
        Matcher ext = Pattern.compile("\"([^\"]+)\"").matcher(body);
        while (ext.find()) {
            if (".runar.java".equals(ext.group(1))) return true;
        }
        return false;
    }

    /**
     * Canonicalize a raw canonical-ANF JSON string for cross-side comparison:
     * parse generically (not into the typed {@code AnfProgram} model — a
     * typed round-trip would silently drop any field the model doesn't carry,
     * on either side), strip {@code sourceLoc} recursively (debug-only, not
     * part of the conformance boundary — Java's {@code --emit-ir} populates
     * it with Java-specific file/line info that the TS-authored goldens never
     * carry), then re-serialize with {@link Jcs#stringify} — the same
     * canonical serializer the compiler itself uses for {@code --emit-ir},
     * so both sides get byte-identical key ordering, number formatting, and
     * string escaping for free.
     */
    private static String canonicalIr(String rawJson) {
        Object parsed = MiniJson.parse(rawJson);
        Object stripped = stripSourceLoc(parsed);
        return Jcs.stringify(stripped);
    }

    private static Object stripSourceLoc(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String key = (String) e.getKey();
                if ("sourceLoc".equals(key)) continue;
                out.put(key, stripSourceLoc(e.getValue()));
            }
            return out;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object item : list) out.add(stripSourceLoc(item));
            return out;
        }
        return value;
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

    /**
     * Minimal hand-rolled recursive-descent JSON parser, test-harness-only
     * (mirrors the canonicalization helpers the Go/Rust/Python/Zig/Ruby
     * golden harnesses each carry in their own test files — none of them
     * reuse a shared JSON library either). Parses to {@code null},
     * {@link Boolean}, {@link BigInteger} (all ANF IR numbers are integral —
     * a non-integer literal is a parse error, matching {@link Jcs}'s own
     * "canonical JSON does not support floating-point numbers" contract),
     * {@link String}, {@code List<Object>}, or {@code Map<String, Object>} —
     * exactly the shapes {@link Jcs#stringify} accepts, so re-serializing a
     * parsed (and {@code sourceLoc}-stripped) value is a single call.
     *
     * <p>Deliberately does NOT reach into {@code AnfLoader}'s private nested
     * {@code JsonParser} — that type parses straight into the typed ANF IR
     * model (dropping any field the model doesn't carry) and is private to
     * that class.
     */
    private static final class MiniJson {
        private final String s;
        private int pos;

        private MiniJson(String s) {
            this.s = s;
        }

        static Object parse(String s) {
            MiniJson p = new MiniJson(s);
            p.skipWs();
            Object v = p.parseValue();
            p.skipWs();
            if (p.pos != p.s.length()) {
                throw new RuntimeException("trailing content in JSON at offset " + p.pos);
            }
            return v;
        }

        private void skipWs() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        }

        private Object parseValue() {
            skipWs();
            if (pos >= s.length()) {
                throw new RuntimeException("unexpected end of JSON input");
            }
            char c = s.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> { expect("true"); yield Boolean.TRUE; }
                case 'f' -> { expect("false"); yield Boolean.FALSE; }
                case 'n' -> { expect("null"); yield null; }
                default -> parseNumber();
            };
        }

        private void expect(String literal) {
            if (!s.regionMatches(pos, literal, 0, literal.length())) {
                throw new RuntimeException("expected '" + literal + "' at offset " + pos);
            }
            pos += literal.length();
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> out = new LinkedHashMap<>();
            pos++; // consume '{'
            skipWs();
            if (pos < s.length() && s.charAt(pos) == '}') {
                pos++;
                return out;
            }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                if (pos >= s.length() || s.charAt(pos) != ':') {
                    throw new RuntimeException("expected ':' at offset " + pos);
                }
                pos++; // consume ':'
                Object val = parseValue();
                out.put(key, val);
                skipWs();
                if (pos >= s.length()) {
                    throw new RuntimeException("unterminated object at offset " + pos);
                }
                char c = s.charAt(pos);
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; break; }
                throw new RuntimeException("expected ',' or '}' at offset " + pos);
            }
            return out;
        }

        private List<Object> parseArray() {
            List<Object> out = new ArrayList<>();
            pos++; // consume '['
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ']') {
                pos++;
                return out;
            }
            while (true) {
                Object val = parseValue();
                out.add(val);
                skipWs();
                if (pos >= s.length()) {
                    throw new RuntimeException("unterminated array at offset " + pos);
                }
                char c = s.charAt(pos);
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; break; }
                throw new RuntimeException("expected ',' or ']' at offset " + pos);
            }
            return out;
        }

        private String parseString() {
            if (pos >= s.length() || s.charAt(pos) != '"') {
                throw new RuntimeException("expected string at offset " + pos);
            }
            pos++; // consume opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) {
                    throw new RuntimeException("unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') break;
                if (c == '\\') {
                    char esc = s.charAt(pos++);
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            String hex = s.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                        }
                        default -> throw new RuntimeException("bad escape '\\" + esc + "' at offset " + pos);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Object parseNumber() {
            int start = pos;
            if (pos < s.length() && s.charAt(pos) == '-') pos++;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
            boolean isInteger = true;
            if (pos < s.length() && s.charAt(pos) == '.') {
                isInteger = false;
                pos++;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                isInteger = false;
                pos++;
                if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
            }
            String numStr = s.substring(start, pos);
            if (numStr.isEmpty() || numStr.equals("-")) {
                throw new RuntimeException("invalid number at offset " + start);
            }
            if (!isInteger) {
                throw new RuntimeException(
                    "canonical ANF JSON does not support non-integer numbers: " + numStr);
            }
            return new BigInteger(numStr);
        }
    }

    // ------------------------------------------------------------------
    // N-124: classifyFixture must FAIL on a fixture with no resolvable
    // source.json / .runar.java source and FAIL on a fixture with a missing
    // IR or hex golden, instead of silently dropping any of these into an
    // unasserted bucket (or, for the missing-source.json case, vanishing
    // from the sweep entirely). These exercise classifyFixture directly
    // against synthetic, throwaway fixture directories (via @TempDir) so
    // they do not touch the real conformance corpus.
    // ------------------------------------------------------------------

    /**
     * What this proves: a fixture directory with no {@code source.json} at
     * all is classified as a FAILURE (kind {@code missing-source}), not
     * silently skipped from every bucket as the old
     * {@code continue; // not a fixture} did.
     *
     * <p>What this does not prove: that the real conformance/tests corpus
     * contains such a directory today — it does not; every entry under
     * {@code conformance/tests} ships a {@code source.json}.
     */
    @Test
    void classifyFixtureFailsOnMissingSourceJson(@TempDir Path tmp) throws IOException {
        // No source.json written at all.
        FixtureOutcome outcome = classifyFixture(tmp);

        assertEquals(Kind.FAILED, outcome.kind(),
            "a fixture directory with no source.json must be a failure, not silently skipped");
        assertTrue(outcome.detail().startsWith("missing-source"),
            "expected a missing-source failure, got: " + outcome.detail());
    }

    /**
     * What this proves: a fixture whose {@code source.json} has no
     * {@code .runar.java} entry (and is not allowlist-excluded) is a
     * FAILURE (kind {@code missing-source}), not the old unasserted
     * {@code missingSource} bucket.
     *
     * <p>What this does not prove: that the real conformance corpus
     * contains such a fixture today — it does not (frontend parity
     * requires every fixture to ship a {@code .runar.java} source).
     */
    @Test
    void classifyFixtureFailsOnMissingJavaSourceEntry(@TempDir Path tmp) throws IOException {
        Files.writeString(tmp.resolve("source.json"), "{\"sources\":{}}");

        FixtureOutcome outcome = classifyFixture(tmp);

        assertEquals(Kind.FAILED, outcome.kind());
        assertTrue(outcome.detail().startsWith("missing-source"),
            "expected a missing-source failure, got: " + outcome.detail());
    }

    /**
     * What this proves: classifyFixture SKIPS (not fails) a fixture whose
     * {@code source.json} {@code compilers} allowlist excludes "java" —
     * matching the existing {@code isJavaAllowed} contract — even when that
     * fixture has no resolvable {@code .runar.java} source, which on its
     * own would be a failure per the test above. The allowlist check must
     * run before the missing-source check.
     */
    @Test
    void classifyFixtureSkipsAllowlistExcludedFixtureWithNoSource(@TempDir Path tmp) throws IOException {
        Files.writeString(tmp.resolve("source.json"), "{\"compilers\":[\"go\"]}");
        // No .runar.java entry, no .runar.java file — legitimate, since the
        // allowlist excludes java for this fixture.

        FixtureOutcome outcome = classifyFixture(tmp, List.of(tmp.getFileName().toString()));

        assertEquals(Kind.SKIPPED, outcome.kind(),
            "an allowlist-excluded fixture must be skipped, not failed: " + outcome);
    }

    /**
     * What this proves: classifyFixture SKIPS (not fails) a fixture whose
     * {@code source.json} lists {@code ".runar.java"} in a
     * {@code parserSkip} array — the real, documented exclusion the
     * {@code fixed-array-index} / {@code fixed-array-write} fixtures use
     * (FixedArray&lt;T, N&gt; is a javac parse error; see
     * docs/formats/java.md). Added after the first real-corpus run of this
     * fix surfaced these two fixtures as "missing-source" failures: ships
     * no {@code .runar.java} entry in {@code sources}, but for a documented
     * reason distinct from the IR/hex-only {@code compilers} allowlist, so
     * it needed its own skip path rather than being folded into a failure.
     */
    /**
     * N-389 (R145). What these three tests prove: an allowlist-excluded
     * fixture that is NOT named in the not-compilable set is attempted, not
     * skipped (here it has no source, so it surfaces as missing-source); a
     * named fixture whose allowlist does not exclude java is a
     * stale-expected-not-compilable failure; and a non-list {@code compilers}
     * value fails closed.
     *
     * <p>What they do not prove: the byte comparison for such a fixture
     * (java refuses every Go-only fixture today, so the real-corpus sweep
     * names all five); the real corpus has no non-list {@code compilers}
     * value.
     */
    @Test
    void classifyFixtureCompilesAllowlistExcludedButUnnamedFixture(@TempDir Path tmp) throws IOException {
        Files.writeString(tmp.resolve("source.json"), "{\"compilers\":[\"go\"]}");

        FixtureOutcome outcome = classifyFixture(tmp);

        assertEquals(Kind.FAILED, outcome.kind(),
            "an allowlist-excluded fixture that is not named must be attempted, not skipped: " + outcome);
        assertTrue(outcome.detail().startsWith("missing-source"),
            "expected a missing-source failure, got: " + outcome.detail());
    }

    @Test
    void classifyFixtureFlagsStaleNamedEntry(@TempDir Path tmp) throws IOException {
        Files.writeString(tmp.resolve("source.json"), "{\"compilers\":[\"go\",\"java\"]}");

        FixtureOutcome outcome = classifyFixture(tmp, List.of(tmp.getFileName().toString()));

        assertEquals(Kind.FAILED, outcome.kind());
        assertTrue(outcome.detail().startsWith("stale-expected-not-compilable"),
            "expected a stale-expected-not-compilable failure, got: " + outcome.detail());
    }

    @Test
    void classifyFixtureFailsClosedOnNonListCompilers(@TempDir Path tmp) throws IOException {
        Files.writeString(tmp.resolve("source.json"), "{\"compilers\":\"go\"}");

        assertThrows(IllegalStateException.class, () -> classifyFixture(tmp));
    }

    @Test
    void classifyFixtureSkipsParserSkipExcludedFixtureWithNoSource(@TempDir Path tmp) throws IOException {
        Files.writeString(tmp.resolve("source.json"),
            "{\"sources\":{},\"parserSkip\":[\".runar.java\"],"
                + "\"parserSkipReason\":\"FixedArray is unsupported on the Java surface\"}");
        // No .runar.java entry, no .runar.java file — legitimate, since
        // parserSkip excludes java for this fixture.

        FixtureOutcome outcome = classifyFixture(tmp);

        assertEquals(Kind.SKIPPED, outcome.kind(),
            "a parserSkip-excluded fixture must be skipped, not failed: " + outcome);
    }

    /**
     * What this proves: classifyFixture treats a missing
     * {@code expected-ir.json} as a FAILURE (kind {@code missing-golden-ir}),
     * not as "nothing to compare against" — before N-124 the harness never
     * read or compared this golden at all, so an IR-only regression could
     * pass unnoticed. The dummy {@code .runar.java} file's contents are
     * irrelevant: the golden-existence check runs before the compiler does.
     *
     * <p>What this does not prove: that the real conformance corpus is
     * missing this golden for any fixture today — it is not; every fixture
     * ships both goldens.
     */
    @Test
    void classifyFixtureFailsOnMissingIrGolden(@TempDir Path tmp) throws IOException {
        Files.writeString(tmp.resolve("source.json"),
            "{\"sources\":{\".runar.java\":\"Dummy.runar.java\"}}");
        Files.writeString(tmp.resolve("Dummy.runar.java"), "// not compiled by this test");
        // expected-ir.json deliberately absent; expected-script.hex irrelevant
        // (the IR-golden check runs first).

        FixtureOutcome outcome = classifyFixture(tmp);

        assertEquals(Kind.FAILED, outcome.kind());
        assertTrue(outcome.detail().startsWith("missing-golden-ir"),
            "expected a missing-golden-ir failure, got: " + outcome.detail());
    }

    /**
     * What this proves: classifyFixture treats a missing
     * {@code expected-script.hex} as a FAILURE (kind
     * {@code missing-golden-hex}), not the old "skip silently" behavior
     * (a bare {@code continue} that counted the fixture nowhere). Isolated
     * from the IR-golden case above by giving the fixture an
     * {@code expected-ir.json} too, so the IR-golden check passes and the
     * hex-golden check is what's actually exercised; the compiler is never
     * invoked either way since both golden-existence checks run first.
     *
     * <p>What this does not prove: the IR/hex comparison logic itself when
     * both goldens ARE present (covered by the real-corpus run in
     * {@code allFixturesProduceByteIdenticalHex}).
     */
    @Test
    void classifyFixtureFailsOnMissingHexGolden(@TempDir Path tmp) throws IOException {
        Files.writeString(tmp.resolve("source.json"),
            "{\"sources\":{\".runar.java\":\"Dummy.runar.java\"}}");
        Files.writeString(tmp.resolve("Dummy.runar.java"), "// not compiled by this test");
        Files.writeString(tmp.resolve("expected-ir.json"), "{}");
        // expected-script.hex deliberately absent.

        FixtureOutcome outcome = classifyFixture(tmp);

        assertEquals(Kind.FAILED, outcome.kind());
        assertTrue(outcome.detail().startsWith("missing-golden-hex"),
            "expected a missing-golden-hex failure, got: " + outcome.detail());
    }

    /**
     * What this proves: classifyFixture's new IR comparison actually FIRES
     * and catches a genuine mismatch — the regression guard for the item's
     * headline Java defect ("checks no IR golden"). Without this test,
     * deleting the {@code actualIrCanonical.equals(expectedIrCanonical)}
     * check would leave every other test green: the missing-golden tests
     * above short-circuit on existence before any comparison runs, the
     * {@code canonicalIr*} tests below never call {@code classifyFixture},
     * and the real corpus has no IR mismatches today. This test points a
     * fixture at the real, compilable {@code P2PKH.runar.java} (so the
     * compiler actually runs) but gives it a deliberately wrong
     * {@code expected-ir.json} and {@code expected-script.hex}, so both
     * comparisons must reject it.
     *
     * <p>What this does not prove: anything about a real conformance
     * fixture's IR — the golden here is synthetic and wrong by
     * construction.
     */
    @Test
    void classifyFixtureFailsOnIrMismatch(@TempDir Path tmp) throws IOException {
        Path repoRoot = locateConformanceDir().getParent().getParent();
        Path p2pkhSource = repoRoot.resolve(
            "examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java");
        assertTrue(Files.exists(p2pkhSource), "fixture source missing: " + p2pkhSource);

        // An absolute path in the ".runar.java" entry resolves as-is
        // (Path#resolve returns an absolute argument unchanged), so this
        // points classifyFixture at the real, compilable P2PKH contract
        // without copying it into the temp fixture dir.
        String sourceJson = "{\"sources\":{\".runar.java\":\""
            + p2pkhSource.toString().replace("\\", "\\\\") + "\"}}";
        Files.writeString(tmp.resolve("source.json"), sourceJson);
        Files.writeString(tmp.resolve("expected-ir.json"), "{\"bogus\":true}");
        Files.writeString(tmp.resolve("expected-script.hex"), "00");

        FixtureOutcome outcome = classifyFixture(tmp);

        assertEquals(Kind.FAILED, outcome.kind());
        assertTrue(outcome.detail().startsWith("ir-mismatch"),
            "expected an ir-mismatch failure (IR comparison must fire before hex), got: " + outcome.detail());
    }

    // ------------------------------------------------------------------
    // N-124: canonicalIr / stripSourceLoc / MiniJson — the comparison must
    // ignore sourceLoc (Java's --emit-ir populates it; the TS-authored
    // goldens never carry it) and must be insensitive to key order and
    // whitespace, exactly like the Go/Rust/Python/Zig/Ruby harnesses'
    // canonicalizers.
    // ------------------------------------------------------------------

    /**
     * What this proves: canonicalIr strips {@code sourceLoc} (at any nesting
     * depth) before comparison, so an actual-side value that carries
     * {@code sourceLoc} (as Java's real {@code --emit-ir} output does) can
     * still byte-match a golden that never carries it.
     *
     * <p>What this does not prove: that Jcs.stringify's escaping/number
     * formatting matches the TS reference byte-for-byte for every value
     * shape — that is exercised by {@code JcsTest} and by the real-corpus
     * run above.
     */
    @Test
    void canonicalIrStripsSourceLocAtAnyDepth() {
        String withSourceLoc = "{\"name\":\"t0\",\"sourceLoc\":{\"file\":\"X.java\",\"line\":1},"
            + "\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}}";
        String withoutSourceLoc = "{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}}";

        assertEquals(canonicalIr(withoutSourceLoc), canonicalIr(withSourceLoc));
    }

    /**
     * What this proves: canonicalIr is insensitive to source key order and
     * whitespace (the golden file is checked in pretty-printed with
     * 2-space indent; the actual CLI output is compact) — both canonicalize
     * to the same string.
     */
    @Test
    void canonicalIrIsOrderAndWhitespaceInsensitive() {
        String compact = "{\"b\":2,\"a\":1}";
        String pretty = "{\n  \"a\": 1,\n  \"b\": 2\n}";

        assertEquals(canonicalIr(compact), canonicalIr(pretty));
    }

    /**
     * What this proves: canonicalIr detects a genuine value mismatch (not a
     * vacuous "always equal" canonicalizer).
     */
    @Test
    void canonicalIrDetectsRealMismatch() {
        assertTrue(!canonicalIr("{\"a\":1}").equals(canonicalIr("{\"a\":2}")));
    }
}
