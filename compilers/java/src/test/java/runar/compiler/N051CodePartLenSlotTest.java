package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * N-051 ("TaffyTail") — the {@code SIZE(_codePart)} pin is always an equality.
 *
 * <p>A stateful contract with a variable-length state section pins the length
 * of the spender-supplied {@code _codePart} with
 * {@code OP_DUP <04 LL LL LL LL> OP_BIN2NUM OP_NUMEQUAL OP_VERIFY}. When a
 * readonly constructor arg of variable width (ByteString, bigint) is baked into
 * the code, the compiler cannot know the deployed length. It used to fall back
 * to OP_GREATERTHANOREQUAL — a lower bound — and a stranger could then claim a
 * truncated {@code _codePart} that ends at a 0x6a byte inside the baked value
 * and plant attacker code in the continuation.
 *
 * <p>The fix keeps the comparison OP_NUMEQUAL and records the length field as a
 * {@code codePartLenSlots} entry the SDK fills in at deploy time. A pin that IS
 * exact at compile time gets no slot.
 */
class N051CodePartLenSlotTest {

    /** The TS reference contract: {@code tag} is a variable-width readonly ByteString. */
    private static final String TAFFY_TAIL = String.join("\n",
        "import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';",
        "import type { ByteString, PubKey, Sig } from 'runar-lang';",
        "",
        "class TaffyTailVault extends StatefulSmartContract {",
        "  message: ByteString;",
        "  readonly tag: ByteString;",
        "  readonly owner: PubKey;",
        "",
        "  constructor(message: ByteString, tag: ByteString, owner: PubKey) {",
        "    super(message, tag, owner);",
        "    this.message = message;",
        "    this.tag = tag;",
        "    this.owner = owner;",
        "  }",
        "",
        "  public burn(sig: Sig) {",
        "    assert(checkSig(sig, this.owner));",
        "  }",
        "",
        "  public post(next: ByteString, claimedTag: ByteString) {",
        "    assert(claimedTag === this.tag);",
        "    this.addOutput(extractAmount(this.txPreimage), next);",
        "  }",
        "}",
        "");

    /** Same shape, but every readonly arg is fixed-width: the pin is exact at compile time. */
    private static final String FIXED_WIDTH = String.join("\n",
        "import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';",
        "import type { ByteString, PubKey, Sig } from 'runar-lang';",
        "",
        "class FixedWidthVault extends StatefulSmartContract {",
        "  message: ByteString;",
        "  readonly owner: PubKey;",
        "",
        "  constructor(message: ByteString, owner: PubKey) {",
        "    super(message, owner);",
        "    this.message = message;",
        "    this.owner = owner;",
        "  }",
        "",
        "  public burn(sig: Sig) {",
        "    assert(checkSig(sig, this.owner));",
        "  }",
        "",
        "  public post(next: ByteString) {",
        "    this.addOutput(extractAmount(this.txPreimage), next);",
        "  }",
        "}",
        "");

    private static final Pattern PIN = Pattern.compile("7604([0-9a-f]{8})81(9c|a2)69");

    @Test
    void variableWidthReadonlyArgGetsAnEqualityPinAndADeployTimeSlot() throws IOException {
        for (boolean fold : List.of(false, true)) {
            String label = "fold " + (fold ? "ON" : "OFF");
            String artifact = compileArtifact("TaffyTailVault", TAFFY_TAIL, fold);
            String script = stringField(artifact, "script");

            List<Integer> pinValueOffsets = pinValueOffsets(script, label);
            assertFalse(pinValueOffsets.isEmpty(), label + ": TaffyTail must carry a SIZE(_codePart) pin");

            List<Integer> slots = slotOffsets(artifact);
            assertEquals(pinValueOffsets, slots,
                label + ": codePartLenSlots must name exactly the pin length fields (the byte after 04)");
            for (int off : slots) {
                assertEquals("04", script.substring((off - 1) * 2, off * 2), label);
                assertEquals("819c69", script.substring((off + 4) * 2, (off + 7) * 2), label);
            }
            assertTrue(artifact.contains("\"codeSepIndexSlots\""), label);
            assertTrue(artifact.indexOf("\"codePartLenSlots\"") > artifact.indexOf("\"codeSepIndexSlots\""),
                label + ": codePartLenSlots must follow codeSepIndexSlots");
            assertTrue(artifact.contains("\"codePartLenSlots\": [{\"byteOffset\": " + slots.get(0) + "}]"),
                label + ": each entry carries exactly one key, byteOffset");
            if (!fold) {
                // Cross-tier: the TypeScript reference compiler, fold OFF, emits a
                // 1317-byte template with the slot at byte 959.
                assertEquals(1317, script.length() / 2, "template length must match the TS reference");
                assertEquals(List.of(959), slots, "slot offset must match the TS reference");
            }
        }
    }

    @Test
    void fixedWidthReadonlyArgsKeepAnExactPinAndNoSlot() throws IOException {
        for (boolean fold : List.of(false, true)) {
            String label = "fold " + (fold ? "ON" : "OFF");
            String artifact = compileArtifact("FixedWidthVault", FIXED_WIDTH, fold);
            String script = stringField(artifact, "script");
            assertFalse(pinValueOffsets(script, label).isEmpty(),
                label + ": a variable-length state section must carry a SIZE(_codePart) pin");
            assertFalse(artifact.contains("codePartLenSlots"),
                label + ": an exact compile-time pin must not produce a codePartLenSlots field");
        }
    }

    // ------------------------------------------------------------------

    /** Offsets of the 4-byte length field of every pin; fails on a lower-bound pin. */
    private static List<Integer> pinValueOffsets(String script, String label) {
        List<Integer> out = new ArrayList<>();
        Matcher m = PIN.matcher(script);
        int from = 0;
        while (m.find(from)) {
            if (m.start() % 2 != 0) {
                from = m.start() + 1;
                continue;
            }
            assertEquals("9c", m.group(2),
                label + ": SIZE(_codePart) pin at byte " + (m.start() / 2)
                    + " uses OP_GREATERTHANOREQUAL — a lower bound accepts a truncated code part");
            out.add(m.start() / 2 + 2);
            from = m.end();
        }
        return out;
    }

    private static List<Integer> slotOffsets(String json) {
        List<Integer> out = new ArrayList<>();
        Matcher arr = Pattern.compile("\"codePartLenSlots\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(json);
        if (!arr.find()) return out;
        Matcher n = Pattern.compile("\"byteOffset\"\\s*:\\s*(\\d+)").matcher(arr.group(1));
        while (n.find()) out.add(Integer.valueOf(n.group(1)));
        return out;
    }

    private static String stringField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        assertTrue(m.find(), "missing string field \"" + key + "\"");
        return m.group(1);
    }

    private static String compileArtifact(String name, String src, boolean fold) throws IOException {
        Path dir = Files.createTempDirectory("runar-n051");
        Path source = dir.resolve(name + ".runar.ts");
        Path out = dir.resolve(name + ".json");
        try {
            Files.writeString(source, src);
            List<String> args = new ArrayList<>(List.of(
                "--source", source.toString(), "--emit-artifact", out.toString()));
            if (!fold) args.add("--disable-constant-folding");
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            PrintStream outPs = new PrintStream(stdout, true, StandardCharsets.UTF_8);
            PrintStream errPs = new PrintStream(stderr, true, StandardCharsets.UTF_8);
            int exit = new Cli(outPs, errPs).run(args.toArray(new String[0]));
            assertEquals(0, exit, "--emit-artifact failed: " + stderr.toString(StandardCharsets.UTF_8));
            return Files.readString(out);
        } finally {
            Files.deleteIfExists(source);
            Files.deleteIfExists(out);
            Files.deleteIfExists(dir);
        }
    }
}
