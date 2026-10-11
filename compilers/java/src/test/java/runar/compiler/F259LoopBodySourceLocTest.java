package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * F-259 — an unrolled loop body's opcodes map to the body statement's line,
 * not to the {@code for} line.
 *
 * <p>Before the fix {@code StackLower.lowerLoop} lowered every body binding
 * without updating {@code currentSourceLoc}, so every opcode of every unrolled
 * iteration inherited the enclosing loop binding's location (the {@code for}
 * line). Mirrors
 * {@code packages/runar-compiler/src/__tests__/f259-loop-body-source-loc.test.ts}.
 *
 * <p>Convention (same in all 7 tiers): each body binding's own location is used
 * while it lowers; a body binding without one keeps the loop's location. The
 * per-iteration iteration-variable push stays on the {@code for} line.
 *
 * <p>What this proves: end to end through the CLI's {@code --emit-source-map}
 * on the Java surface of examples/java/.../bounded-loop, every body op of all
 * five unrolled iterations maps to the body line and column, and only the five
 * iteration-variable pushes (OP_0..OP_4) map to the {@code for} line.
 *
 * <p>What this does not prove: anything about the other tiers, nested loops,
 * or body bindings the ANF lowerer leaves without a location. It equates byte
 * index with opcodeIndex, which it checks holds (the script has no push-data
 * opcodes).
 */
class F259LoopBodySourceLocTest {

    private static final Path SOURCE = Path.of(
        "../../examples/java/src/main/java/runar/examples/bounded-loop/BoundedLoop.runar.java");

    private static final Pattern MAPPING = Pattern.compile(
        "\\{\"opcodeIndex\": (\\d+), \"sourceFile\": \"[^\"]*\", \"line\": (\\d+), \"column\": (\\d+)\\}");

    @Test
    void loopBodyOpsMapToTheBodyLine(@TempDir Path tmp) throws Exception {
        Path sm = tmp.resolve("sm.json");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exit = new Cli(new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8)).run(new String[] {
                "--source", SOURCE.toString(), "--disable-constant-folding", "--hex",
                "--emit-source-map", sm.toString()});
        assertEquals(0, exit, "stderr=" + err.toString(StandardCharsets.UTF_8));
        String hex = out.toString(StandardCharsets.UTF_8).trim();

        // Every byte is a one-byte opcode (no 0x01..0x4e pushes), so the byte
        // index is the opcode index.
        for (int i = 0; i < hex.length(); i += 2) {
            int op = Integer.parseInt(hex.substring(i, i + 2), 16);
            assertTrue(op == 0 || op > 0x4e, "push-data opcode at byte " + i / 2 + ": " + hex);
        }
        Map<Integer, Integer> iterPushes = Map.of(1, 0x00, 9, 0x51, 17, 0x52, 25, 0x53, 33, 0x54);
        for (Map.Entry<Integer, Integer> e : iterPushes.entrySet()) {
            int at = e.getKey();
            assertEquals((int) e.getValue(), Integer.parseInt(hex.substring(2 * at, 2 * at + 2), 16),
                "iteration push at opcode " + at + ": " + hex);
        }

        List<String> lines = Files.readAllLines(SOURCE);
        int[] forPos = find(lines, "for (Bigint i", "for");
        int[] bodyPos = find(lines, "sum = sum.plus(start).plus(i)", "sum");

        List<int[]> loopOps = new ArrayList<>();
        Matcher m = MAPPING.matcher(Files.readString(sm));
        while (m.find()) {
            int idx = Integer.parseInt(m.group(1));
            if (idx >= 1 && idx <= 39) {
                loopOps.add(new int[] {idx, Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3))});
            }
        }
        assertEquals(39, loopOps.size(), "loop-op mappings");
        for (int[] op : loopOps) {
            int[] want = iterPushes.containsKey(op[0]) ? forPos : bodyPos;
            assertEquals(List.of(op[0], want[0], want[1]), List.of(op[0], op[1], op[2]),
                "opcode " + op[0]);
        }
    }

    private static int[] find(List<String> lines, String needle, String anchor) {
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).contains(needle)) {
                return new int[] {i + 1, lines.get(i).indexOf(anchor)};
            }
        }
        throw new AssertionError("needle not in source: " + needle);
    }
}
