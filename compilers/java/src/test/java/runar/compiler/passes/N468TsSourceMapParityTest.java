package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import runar.compiler.Cli;

/**
 * N-468. Compiling the same {@code .runar.ts} source with constant folding
 * off, the Java source map diverged from the TypeScript reference on 32 of
 * the 90 {@code examples/ts} contracts, in both directions:
 *
 * <ul>
 *   <li>TS maps the first op of an if-arm to the {@code if}'s statement when
 *       that op carries no location of its own (TS emit keeps the pending
 *       location across OP_IF and clears it only after a leaf op or
 *       OP_ENDIF). Java's emit overwrote the pending location with every
 *       op's (possibly absent) location and consumed it after one opcode, so
 *       ~77.8k builtin-expansion opcodes (reverseBytes, EC, P-256/P-384,
 *       SLH-DSA, WOTS, math) were unmapped.</li>
 *   <li>TS starts every ANF sub-context (if/ternary/short-circuit arms, loop
 *       bodies) with no location; only a statement inside the arm sets one.
 *       Java's sub-context inherited the enclosing statement's location, so
 *       the arms of {@code &&}/{@code ||}, ternaries and FixedArray index
 *       dispatch were mapped where TS leaves them unmapped.</li>
 * </ul>
 *
 * <p>The reference is the TypeScript tier, pinned in
 * {@code n468_ts_reference_map.json} beside this file as runs
 * {@code [firstOpcode, lastOpcode, line, column]} per example source.
 * Regenerate an entry with
 * {@code runar compile examples/ts/<dir>/<File>.runar.ts -o <dir> --disable-constant-folding --emit-source-map <out.json>}.
 *
 * <p>Proves: for each pinned example, the Java CLI's {@code --emit-source-map}
 * output (fold off, the same flags remediation-logs/N-394/cmp5.py uses) maps
 * exactly the opcodes TS maps, each to the same line and column. The set
 * covers both polarities: boolean-logic / fixed-array-* / nested-if /
 * conditional-data-output / companion-verifier / token-ft / tic-tac-toe
 * (Java mapped what TS does not) and byte-builtins / p256-encode-negate /
 * math-demo (TS mapped what Java did not).
 *
 * <p>Does not prove: anything about examples not pinned here (the 90-example
 * cmp5.py sweep covers those), fold-ON maps, or other tiers. The TS map is
 * pinned, not recomputed, so a later TS change will not be noticed here.
 */
class N468TsSourceMapParityTest {

    private static final Pattern KEY = Pattern.compile("\"([^\"]+)\":\\s*\\[");
    private static final Pattern RUN = Pattern.compile("\\[(\\d+),\\s*(\\d+),\\s*(\\d+),\\s*(\\d+)\\]");
    private static final Pattern MAPPING = Pattern.compile(
        "\"opcodeIndex\":\\s*(\\d+),\\s*\"sourceFile\":\\s*\"[^\"]*\",\\s*\"line\":\\s*(\\d+),\\s*\"column\":\\s*(\\d+)");

    @TestFactory
    List<DynamicTest> javaSourceMapMatchesTsReference() throws IOException {
        Path root = locateRepoRoot();
        Path refFile = root.resolve("compilers/java/src/test/java/runar/compiler/passes/n468_ts_reference_map.json");
        Map<String, Map<Integer, String>> reference = parseReference(Files.readString(refFile));
        assertTrue(reference.size() >= 11, "reference map lost entries: " + reference.keySet());

        List<DynamicTest> tests = new ArrayList<>();
        for (Map.Entry<String, Map<Integer, String>> e : reference.entrySet()) {
            String rel = e.getKey();
            Map<Integer, String> want = e.getValue();
            tests.add(DynamicTest.dynamicTest(rel, () -> {
                Path src = root.resolve("examples/ts").resolve(rel);
                Path out = Files.createTempFile("n468-", ".json");
                try {
                    int exit = runCli("--source", src.toString(), "--disable-constant-folding",
                        "--emit-source-map", out.toString(), "--hex");
                    assertEquals(0, exit, "runar-java failed on " + rel);
                    Map<Integer, String> got = new TreeMap<>();
                    Matcher m = MAPPING.matcher(Files.readString(out));
                    while (m.find()) {
                        got.put(Integer.parseInt(m.group(1)), m.group(2) + ":" + m.group(3));
                    }
                    TreeSet<Integer> all = new TreeSet<>(want.keySet());
                    all.addAll(got.keySet());
                    List<String> diffs = new ArrayList<>();
                    for (int i : all) {
                        String w = want.get(i);
                        String g = got.get(i);
                        if (w == null ? g != null : !w.equals(g)) {
                            diffs.add("#" + i + ": TS " + w + " / Java " + g);
                        }
                    }
                    assertTrue(diffs.isEmpty(), rel + ": " + diffs.size()
                        + " opcodes differ from the TS map: "
                        + diffs.subList(0, Math.min(10, diffs.size())));
                } finally {
                    Files.deleteIfExists(out);
                }
            }));
        }
        return tests;
    }

    private static Map<String, Map<Integer, String>> parseReference(String json) {
        Map<String, Map<Integer, String>> out = new LinkedHashMap<>();
        Matcher k = KEY.matcher(json);
        List<int[]> bounds = new ArrayList<>();
        List<String> keys = new ArrayList<>();
        while (k.find()) {
            keys.add(k.group(1));
            bounds.add(new int[] {k.end()});
        }
        for (int i = 0; i < keys.size(); i++) {
            int start = bounds.get(i)[0];
            int end = i + 1 < keys.size() ? json.lastIndexOf('"', json.indexOf(keys.get(i + 1), start)) : json.length();
            Map<Integer, String> map = new TreeMap<>();
            Matcher r = RUN.matcher(json.substring(start, end));
            while (r.find()) {
                int first = Integer.parseInt(r.group(1));
                int last = Integer.parseInt(r.group(2));
                for (int op = first; op <= last; op++) map.put(op, r.group(3) + ":" + r.group(4));
            }
            out.put(keys.get(i), map);
        }
        return out;
    }

    private static Path locateRepoRoot() throws IOException {
        Path cwd = Paths.get("").toAbsolutePath();
        for (Path p = cwd; p != null; p = p.getParent()) {
            if (Files.isDirectory(p.resolve("examples").resolve("ts"))
                    && Files.isDirectory(p.resolve("compilers").resolve("java"))) {
                return p;
            }
        }
        throw new IOException("repo root (examples/ts) not found above " + cwd);
    }

    private static int runCli(String... args) {
        PrintStream outPs = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        PrintStream errPs = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        return new Cli(outPs, errPs).run(args);
    }
}
