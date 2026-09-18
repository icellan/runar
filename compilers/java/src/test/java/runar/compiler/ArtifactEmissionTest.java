package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.junit.jupiter.api.Test;

/**
 * R-007 / CL-BUG-044: the Java compiler must produce a deployable artifact.
 *
 * <p>Before this test the Java tier emitted only a bare Bitcoin Script hex
 * string. {@code PlaceholderOp} and {@code PushCodeSepIndexOp} wrote a literal
 * {@code 00} byte and recorded nothing, and {@link Cli} had no artifact
 * serialisation at all — so {@code packages/runar-java}'s {@code RunarArtifact}
 * (which reads {@code constructorSlots}, {@code codeSepIndexSlots},
 * {@code codeSeparatorIndex} and {@code codeSeparatorIndices}) could never be
 * fed from the Java compiler's own output. Any Java-tier contract with
 * constructor arguments, and every stateful contract, was undeployable.
 *
 * <h2>What these tests prove</h2>
 * <ul>
 *   <li>The Java CLI emits an artifact JSON carrying real byte offsets, not
 *       placeholders.</li>
 *   <li>The recorded {@code constructorSlots} offset is <em>correct</em>: a
 *       constructor argument spliced in at that offset produces the canonical
 *       P2PKH template. A merely-present-but-wrong offset fails.</li>
 *   <li>Every recorded {@code codeSeparatorIndex} / {@code codeSeparatorIndices}
 *       entry points at a byte that really is {@code 0xab} (OP_CODESEPARATOR)
 *       in the emitted script.</li>
 *   <li><b>Cross-tier agreement</b>: for {@code CodeSepMatrix.runar.ts} the
 *       Java tier's offsets equal the checked-in artifact golden at
 *       {@code conformance/sdk-vertical/artifacts/CodeSepMatrix.json}, which was
 *       produced by the TypeScript tier and is the same artifact the SDK
 *       vertical conformance suite replays against every SDK.</li>
 *   <li>Recording the offsets is purely observational: the artifact's
 *       {@code script} is byte-identical to what {@code --hex} emits.</li>
 * </ul>
 *
 * <h2>What these tests do NOT prove</h2>
 * <ul>
 *   <li>They do not prove the Java artifact is complete. {@code asm},
 *       {@code sigHashType} and fixed-array ABI regrouping are still absent
 *       from the Java tier (see the class comment on the artifact writer in
 *       {@link Cli}); {@code RunarArtifact} tolerates their absence but the
 *       SDK loses the corresponding behaviour.</li>
 *   <li>They do not execute the resulting script or broadcast a transaction —
 *       nothing here proves a Java-built locking script is spendable on a
 *       node. That remains the integration suite's job.</li>
 *   <li>Cross-tier agreement is asserted for two contracts, not for the whole
 *       conformance corpus.</li>
 * </ul>
 */
class ArtifactEmissionTest {

    // ------------------------------------------------------------------
    // 1. constructorSlots offset is present AND correct
    // ------------------------------------------------------------------

    /**
     * The canonical P2PKH lock is {@code OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY
     * OP_CHECKSIG}. The compiler emits the {@code <pkh>} push as a one-byte
     * {@code OP_0} placeholder, so the un-spliced script is {@code 76a90088ac}
     * and the constructor slot must name byte offset 2.
     *
     * <p>Presence alone is worth little, so the test splices a real 20-byte
     * hash into the recorded offset the way {@code ContractScript} does and
     * asserts the result is the canonical P2PKH template. A slot that merely
     * exists at the wrong offset produces a different (invalid) script.
     */
    @Test
    void p2pkhArtifactRecordsAConstructorSlotAtTheRealPlaceholderOffset() throws IOException {
        Path repoRoot = locateRepoRoot();
        Path source = repoRoot.resolve(
            "examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java");
        assertTrue(Files.exists(source), "missing P2PKH example at " + source);

        String artifact = compileArtifact(source);

        String script = stringField(artifact, "script");
        assertEquals("76a90088ac", script, "P2PKH locking script (placeholder un-spliced)");

        List<int[]> slots = intPairs(artifact, "constructorSlots", "paramIndex", "byteOffset");
        assertEquals(1, slots.size(), "P2PKH has exactly one constructor slot; got " + slots);
        assertEquals(0, slots.get(0)[0], "paramIndex");
        int byteOffset = slots.get(0)[1];

        // The recorded offset must point at the OP_0 placeholder byte.
        assertEquals("00", byteAt(script, byteOffset),
            "byte at constructorSlots[0].byteOffset should be the OP_0 placeholder");

        // Splice a real push at that offset and check the bytes land where
        // the canonical P2PKH template requires.
        String pkh = "0102030405060708090a0b0c0d0e0f1011121314"; // 20 bytes
        String spliced = script.substring(0, byteOffset * 2)
            + "14" + pkh
            + script.substring((byteOffset + 1) * 2);
        assertEquals("76a914" + pkh + "88ac", spliced,
            "splicing the constructor arg at the recorded offset must yield canonical P2PKH");
    }

    // ------------------------------------------------------------------
    // 2. cross-tier agreement against a checked-in artifact golden
    // ------------------------------------------------------------------

    /**
     * {@code conformance/sdk-vertical/artifacts/CodeSepMatrix.json} is a
     * checked-in artifact produced by the TypeScript tier and replayed by the
     * SDK vertical conformance suite against every SDK. It is the cross-tier
     * reference for slot offsets: it carries two {@code constructorSlots}, two
     * {@code codeSepIndexSlots}, a {@code codeSeparatorIndex} and three
     * {@code codeSeparatorIndices}.
     *
     * <p>This is the cross-tier bar for R-007. The Go tier
     * ({@code compilers/go/runar-go --source
     * conformance/sdk-vertical/contracts/CodeSepMatrix.runar.ts}) reproduces
     * the same offsets; asserting against the checked-in golden rather than
     * shelling out to the Go binary keeps the test hermetic and avoids
     * depending on a prebuilt sibling-tier binary from a Gradle test.
     */
    @Test
    void codeSepMatrixArtifactMatchesTheCheckedInCrossTierGolden() throws IOException {
        Path repoRoot = locateRepoRoot();
        Path source = repoRoot.resolve("conformance/sdk-vertical/contracts/CodeSepMatrix.runar.ts");
        Path goldenPath = repoRoot.resolve("conformance/sdk-vertical/artifacts/CodeSepMatrix.json");
        assertTrue(Files.exists(source), "missing fixture " + source);
        assertTrue(Files.exists(goldenPath), "missing golden " + goldenPath);

        String golden = Files.readString(goldenPath);
        String artifact = compileArtifact(source);

        // Same script bytes, so offsets are comparable at all.
        assertEquals(stringField(golden, "script"), stringField(artifact, "script"),
            "Java tier must emit the same script bytes as the golden");

        assertEquals(
            intPairs(golden, "constructorSlots", "paramIndex", "byteOffset").stream()
                .map(p -> p[0] + "@" + p[1]).toList(),
            intPairs(artifact, "constructorSlots", "paramIndex", "byteOffset").stream()
                .map(p -> p[0] + "@" + p[1]).toList(),
            "constructorSlots (paramIndex@byteOffset) must match the cross-tier golden");

        assertEquals(
            intPairs(golden, "codeSepIndexSlots", "byteOffset", "codeSepIndex").stream()
                .map(p -> p[0] + "@" + p[1]).toList(),
            intPairs(artifact, "codeSepIndexSlots", "byteOffset", "codeSepIndex").stream()
                .map(p -> p[0] + "@" + p[1]).toList(),
            "codeSepIndexSlots (byteOffset@codeSepIndex) must match the cross-tier golden");

        assertEquals(intField(golden, "codeSeparatorIndex"), intField(artifact, "codeSeparatorIndex"),
            "codeSeparatorIndex must match the cross-tier golden");
        assertEquals(intArray(golden, "codeSeparatorIndices"), intArray(artifact, "codeSeparatorIndices"),
            "codeSeparatorIndices must match the cross-tier golden");
    }

    // ------------------------------------------------------------------
    // 3. codeSeparatorIndex points at a real OP_CODESEPARATOR
    // ------------------------------------------------------------------

    /**
     * A stateful contract compiles with OP_CODESEPARATOR inserted by the
     * compiler. Every recorded index must address a byte that really is
     * {@code 0xab} in the emitted script, and {@code codeSeparatorIndex} must
     * be the last of {@code codeSeparatorIndices} (the "most recent"
     * separator, which is what the BIP-143 subscript is measured from).
     */
    @Test
    void statefulContractRecordsCodeSeparatorIndicesAtRealOpCodeSeparatorBytes() throws IOException {
        Path repoRoot = locateRepoRoot();
        Path source = repoRoot.resolve(
            "examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java");
        assertTrue(Files.exists(source), "missing Counter example at " + source);

        String artifact = compileArtifact(source);
        String script = stringField(artifact, "script");

        Integer csIndex = intField(artifact, "codeSeparatorIndex");
        assertNotNull(csIndex, "stateful contract must record codeSeparatorIndex");
        List<Integer> indices = intArray(artifact, "codeSeparatorIndices");
        assertFalse(indices.isEmpty(), "stateful contract must record codeSeparatorIndices");

        for (int idx : indices) {
            assertEquals("ab", byteAt(script, idx),
                "codeSeparatorIndices entry " + idx + " must address an OP_CODESEPARATOR byte");
        }
        assertEquals(indices.get(indices.size() - 1), csIndex,
            "codeSeparatorIndex must be the last (most recent) separator offset");

        // Cross-tier pin: captured from the Go reference compiler via
        // `compilers/go/runar-go --source <this file>`. R-010 replaced the
        // per-method separators with a single one at offset 1, behind an
        // OP_NOP, so that scriptCode == lockingScript[2:].
        assertEquals(1, csIndex.intValue(), "codeSeparatorIndex must match the Go tier");
        assertEquals(List.of(1), indices, "codeSeparatorIndices must match the Go tier");
    }

    // ------------------------------------------------------------------
    // 4. recording offsets must not move a single emitted byte
    // ------------------------------------------------------------------

    /**
     * Slot recording is observational. The artifact's {@code script} field must
     * be byte-identical to what {@code --hex} prints for the same input, so the
     * change cannot perturb the cross-tier conformance goldens.
     */
    @Test
    void artifactScriptIsByteIdenticalToTheHexOutput() throws IOException {
        Path repoRoot = locateRepoRoot();
        for (String rel : List.of(
            "examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java",
            "examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java",
            "conformance/sdk-vertical/contracts/CodeSepMatrix.runar.ts")) {
            Path source = repoRoot.resolve(rel);
            Result hex = runCli("--source", source.toString(), "--hex", "--disable-constant-folding");
            assertEquals(0, hex.exit, "--hex failed for " + rel + ": " + hex.stderr);
            String artifact = compileArtifact(source);
            assertEquals(hex.stdout.trim(), stringField(artifact, "script"),
                "artifact.script must equal --hex output for " + rel);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Compile {@code source} to an artifact JSON via the CLI and return it. */
    private static String compileArtifact(Path source) throws IOException {
        Path out = Files.createTempFile("runar-artifact", ".json");
        try {
            Result r = runCli(
                "--source", source.toString(),
                "--emit-artifact", out.toString(),
                "--disable-constant-folding");
            assertEquals(0, r.exit, "--emit-artifact failed: " + r.stderr);
            String body = Files.readString(out);
            assertFalse(body.isBlank(), "artifact JSON is empty");
            return body;
        } finally {
            Files.deleteIfExists(out);
        }
    }

    /** Two lowercase hex chars at byte index {@code i} of a hex script. */
    private static String byteAt(String scriptHex, int i) {
        assertTrue(i >= 0 && (i + 1) * 2 <= scriptHex.length(),
            "byte offset " + i + " out of range for a " + (scriptHex.length() / 2) + "-byte script");
        return scriptHex.substring(i * 2, (i + 1) * 2);
    }

    private static String stringField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        assertTrue(m.find(), "missing string field \"" + key + "\"");
        return m.group(1);
    }

    /** Integer field, or null when absent / JSON null. */
    private static Integer intField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+|null)").matcher(json);
        if (!m.find()) return null;
        return "null".equals(m.group(1)) ? null : Integer.valueOf(m.group(1));
    }

    private static List<Integer> intArray(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[([^\\]]*)]").matcher(json);
        List<Integer> out = new ArrayList<>();
        if (!m.find()) return out;
        Matcher n = Pattern.compile("-?\\d+").matcher(m.group(1));
        while (n.find()) out.add(Integer.valueOf(n.group()));
        return out;
    }

    /**
     * Extracts {@code [{a: .., b: ..}, ..]} pairs from an object array field.
     * Tolerates extra keys inside each object — the TypeScript-produced golden
     * carries {@code name} / {@code type} / {@code valueEncoding} alongside the
     * offsets, which the Go tier and the Java SDK's {@code ConstructorSlot} do
     * not model.
     */
    private static List<int[]> intPairs(String json, String key, String a, String b) {
        List<int[]> out = new ArrayList<>();
        Matcher arr = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(json);
        if (!arr.find()) return out;
        Matcher obj = Pattern.compile("\\{[^{}]*}").matcher(arr.group(1));
        while (obj.find()) {
            String o = obj.group();
            Integer av = intField(o, a);
            Integer bv = intField(o, b);
            assertNotNull(av, "missing \"" + a + "\" in " + key + " entry " + o);
            assertNotNull(bv, "missing \"" + b + "\" in " + key + " entry " + o);
            out.add(new int[] {av, bv});
        }
        return out;
    }

    private static Path locateRepoRoot() throws IOException {
        Path cwd = Paths.get("").toAbsolutePath();
        for (Path p = cwd; p != null; p = p.getParent()) {
            if (Files.isDirectory(p.resolve("conformance").resolve("tests"))) return p;
        }
        throw new IOException("repo root (containing conformance/tests) not found above " + cwd);
    }

    private record Result(int exit, String stdout, String stderr) {}

    private static Result runCli(String... args) {
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream outPs = new PrintStream(stdout, true, StandardCharsets.UTF_8);
        PrintStream errPs = new PrintStream(stderr, true, StandardCharsets.UTF_8);
        int exit = new Cli(outPs, errPs).run(args);
        outPs.flush();
        errPs.flush();
        return new Result(exit, stdout.toString(StandardCharsets.UTF_8), stderr.toString(StandardCharsets.UTF_8));
    }
}
