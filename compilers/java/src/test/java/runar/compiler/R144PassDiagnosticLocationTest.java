package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R-144 (CL-BUG-045): AnfLower and StackLower refusals carried no
 * file:line:column, unlike Validate and Typecheck diagnostics in the same tier.
 *
 * <p>Both passes refuse constructs they must not emit, and both already HOLD the
 * position: {@code AnfLower} walks {@code PropertyNode}s and statements that
 * carry a {@link runar.compiler.ir.SourceLocation}, and every {@code AnfBinding}
 * {@code StackLower} lowers carries {@code sourceLoc} — round-tripped through
 * the {@code --ir} JSON, so it is present even when the pass never saw a source
 * file. What was missing is that nothing published it on the way out.
 *
 * <p>The contrast is visible in one run: compiling {@code BigInit.runar.ts}
 * printed a DCE warning reading
 * {@code BigInit.runar.ts:5:2: readonly field 'tag' ...} and, on the very next
 * line, {@code runar-java: anf-lower error: Cannot compile state property
 * 'count' ...} with no position at all.
 *
 * <p>These tests drive the two passes through the real CLI — one from source,
 * one from {@code --ir} — and require the position the pass was holding.
 */
class R144PassDiagnosticLocationTest {

    /**
     * A state property whose initializer does not fit the fixed 8-byte
     * sign-magnitude state word. Refused by {@code AnfLower} (not by Validate or
     * Typecheck), so it exercises the pass-4 arm. `tag` exists only to give the
     * contract a constructor parameter.
     */
    private static final String BIG_STATE_INIT = """
        import { StatefulSmartContract } from 'runar-lang';

        export class BigInit extends StatefulSmartContract {
          count: bigint = 99999999999999999999n;
          readonly tag: bigint;

          constructor(tag: bigint) {
            super(tag);
            this.tag = tag;
          }

          public bump(): void {
            this.count = this.count + 1n;
          }
        }
        """;

    /** file:line:column, the shape Validate.Ctx.formatAt already produces. */
    private static final Pattern LOCATED =
        Pattern.compile("[^\\s:]+\\.runar\\.[a-z]+:\\d+:\\d+: ");

    @Test
    void anfLowerRefusalCarriesFileLineColumn(@TempDir Path tmp) throws Exception {
        Path src = tmp.resolve("BigInit.runar.ts");
        Files.writeString(src, BIG_STATE_INIT);

        Result r = run("--source", src.toString(), "--hex");

        assertEquals(70, r.exit, "expected the anf-lower refusal; stderr=" + r.stderr);
        String line = errorLine(r.stderr);
        assertTrue(
            line.contains("Cannot compile state property 'count'"),
            "wrong diagnostic reached stderr: " + line);
        assertTrue(
            LOCATED.matcher(line).find(),
            "anf-lower refusal carries no file:line:column. The property it refused "
                + "has a sourceLocation and the DCE warning in the same run prints one. "
                + "Line was: " + line);
        assertTrue(
            line.contains("BigInit.runar.ts:4:"),
            "the location must point at the property the pass refused (line 4), not at "
                + "some other node. Line was: " + line);
    }

    /**
     * The {@code --ir} arm: StackLower refuses an unknown builtin. The pass never
     * sees a source file here — the only position available is the one the ANF
     * JSON carried, which is exactly the point.
     */
    @Test
    void stackLowerRefusalCarriesTheBindingLocation(@TempDir Path tmp) throws Exception {
        Path src = tmp.resolve("Simple.runar.ts");
        Files.writeString(src, """
            import { SmartContract, assert } from 'runar-lang';

            export class Simple extends SmartContract {
              readonly limit: bigint;

              constructor(limit: bigint) {
                super(limit);
                this.limit = limit;
              }

              public unlock(x: bigint): void {
                assert(x < this.limit);
              }
            }
            """);

        Path ir = tmp.resolve("simple.ir.json");
        Result emit = run("--source", src.toString(), "--emit-ir-to", ir.toString());
        assertEquals(0, emit.exit, "IR emission failed; stderr=" + emit.stderr);

        // Splice in a binding calling a builtin that does not exist, carrying the
        // location of the statement it stands for. Hand-built, so the location is
        // known exactly and cannot be confused with a neighbour's.
        String binding =
            "{\"name\":\"tBogus\","
                + "\"sourceLoc\":{\"column\":9,\"file\":\"" + jsonEscape(src.toString())
                + "\",\"line\":12},"
                + "\"value\":{\"args\":[\"t0\"],\"func\":\"notARealBuiltin\",\"kind\":\"call\"}},";
        Path bad = tmp.resolve("bad.ir.json");
        Files.writeString(bad, spliceIntoUnlock(Files.readString(ir), binding));

        Result r = run("--ir", bad.toString(), "--hex");

        assertEquals(70, r.exit, "expected the stack-lower refusal; stderr=" + r.stderr);
        String line = errorLine(r.stderr);
        assertTrue(
            line.contains("unknown builtin: 'notARealBuiltin'"),
            "wrong diagnostic reached stderr: " + line);
        assertTrue(
            line.contains(":12:9: "),
            "stack-lower refusal dropped the sourceLoc the binding carried (12:9). "
                + "Line was: " + line);
    }

    /**
     * Control: a refusal on a binding with NO sourceLoc must still print, exactly
     * as it did before — the location is additive, never a precondition.
     */
    @Test
    void refusalWithoutALocationStillPrintsItsMessage(@TempDir Path tmp) throws Exception {
        Path src = tmp.resolve("Simple.runar.ts");
        Files.writeString(src, """
            import { SmartContract, assert } from 'runar-lang';

            export class Simple extends SmartContract {
              readonly limit: bigint;

              constructor(limit: bigint) {
                super(limit);
                this.limit = limit;
              }

              public unlock(x: bigint): void {
                assert(x < this.limit);
              }
            }
            """);

        Path ir = tmp.resolve("simple.ir.json");
        assertEquals(0, run("--source", src.toString(), "--emit-ir-to", ir.toString()).exit);

        String binding =
            "{\"name\":\"tBogus\","
                + "\"value\":{\"args\":[\"t0\"],\"func\":\"notARealBuiltin\",\"kind\":\"call\"}},";
        Path bad = tmp.resolve("bad-noloc.ir.json");
        Files.writeString(bad, spliceIntoUnlock(Files.readString(ir), binding));

        Result r = run("--ir", bad.toString(), "--hex");

        assertEquals(70, r.exit, "stderr=" + r.stderr);
        String line = errorLine(r.stderr);
        assertTrue(
            line.contains("unknown builtin: 'notARealBuiltin'"),
            "a locationless refusal must still carry its message: " + line);
        assertTrue(
            line.startsWith("runar-java: "),
            "a locationless refusal must keep its old shape exactly: " + line);
    }

    /**
     * Insert {@code binding} as the SECOND binding of the {@code unlock} method,
     * so the {@code t0} it references is already bound. The emitted JSON is JCS
     * (compact, keys sorted), so the needle carries no spaces.
     */
    private static String spliceIntoUnlock(String json, String binding) {
        int method = json.indexOf("\"name\":\"unlock\"");
        assertTrue(method > 0, "no unlock method in the emitted IR: " + json);
        int body = json.lastIndexOf("\"body\":[", method);
        assertTrue(body > 0, "unlock has no body array: " + json);
        int second = json.indexOf("},{", body) + 2;
        assertTrue(second > 2, "unlock body has fewer than two bindings: " + json);
        return json.substring(0, second) + binding + json.substring(second);
    }

    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** The last "runar-java: " line on stderr — warnings precede it. */
    private static String errorLine(String stderr) {
        String found = "";
        for (String l : stderr.split("\n")) {
            if (l.startsWith("runar-java: ")) {
                found = l;
            }
        }
        assertTrue(!found.isEmpty(), "no 'runar-java: ' diagnostic on stderr: " + stderr);
        return found;
    }

    private record Result(int exit, String stdout, String stderr) {}

    private Result run(String... args) {
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
            stderr.toString(StandardCharsets.UTF_8));
    }
}
