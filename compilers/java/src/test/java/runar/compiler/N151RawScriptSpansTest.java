package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * N-151: the {@code --emit-artifact} JSON carries {@code rawScriptSpans}
 * exactly as the TS reference does.
 *
 * <p>{@code Emit} always recorded one span per asm() raw-bytes op, but the
 * artifact writer in {@link Cli} never serialised them, so the analyzer and
 * SDKs lost the span metadata for every Java-built raw-script contract. The
 * expected values are the ones pinned by the TS reference test
 * {@code packages/runar-compiler/src/__tests__/raw-script-spans.test.ts}.
 *
 * <p>Proves: for the single-span, consecutive-span, non-default-arity and
 * multi-byte-body shapes the artifact's {@code rawScriptSpans} array equals
 * TS's (offset, length, inArity, outArity), and the key is omitted for a
 * contract with no asm(). Does NOT prove how an SDK or analyzer consumes the
 * spans; cross-tier value parity is
 * {@code conformance/negatives/artifact-flag-parity.test.ts}.
 */
class N151RawScriptSpansTest {

    private static String asmContract(String params, String body) {
        return "import { UnsafeSmartContract, asm } from 'runar-lang';\n\n"
            + "class WithAsm extends UnsafeSmartContract {\n"
            + "  constructor() {\n    super();\n  }\n\n"
            + "  public unlock(" + params + ") {\n" + body + "\n  }\n}\n";
    }

    private static String span(int offset, int length, int in, int out) {
        return "{\"offset\":" + offset + ",\"length\":" + length
            + ",\"inArity\":" + in + ",\"outArity\":" + out + "}";
    }

    @Test
    void singleSpan() throws IOException {
        assertSpans("[" + span(0, 1, 0, 1) + "]",
            asmContract("", "    asm({ body: '51', in_arity: 0, out_arity: 1 });"));
    }

    @Test
    void consecutiveSpans() throws IOException {
        assertSpans("[" + span(0, 1, 0, 1) + "," + span(1, 2, 1, 1) + "]",
            asmContract("", "    asm({ body: '51', in_arity: 0, out_arity: 1 });\n"
                + "    asm({ body: '6151', in_arity: 1, out_arity: 1 });"));
    }

    @Test
    void nonDefaultArities() throws IOException {
        assertSpans("[" + span(0, 1, 2, 1) + "]",
            asmContract("a: bigint, b: bigint", "    asm({ body: '87', in_arity: 2, out_arity: 1 });"));
    }

    @Test
    void multiByteBody() throws IOException {
        assertSpans("[" + span(0, 4, 0, 1) + "]",
            asmContract("", "    asm({ body: '76a90051', in_arity: 0, out_arity: 1 });"));
    }

    @Test
    void omittedWithoutAsm() throws IOException {
        String src = "import { SmartContract, assert } from 'runar-lang';\n\n"
            + "class Always extends SmartContract {\n"
            + "  constructor() { super(); }\n"
            + "  public unlock(): void {\n    assert(1n === 1n);\n  }\n}\n";
        String artifact = compileArtifact(src);
        assertFalse(artifact.contains("\"rawScriptSpans\""),
            "rawScriptSpans must be omitted for a contract with no asm(): " + artifact);
    }

    private static void assertSpans(String expected, String source) throws IOException {
        String artifact = compileArtifact(source);
        Matcher m = Pattern.compile("\"rawScriptSpans\"\\s*:\\s*(\\[[^\\]]*])").matcher(artifact);
        assertNotNull(m.find() ? m.group(1) : null, "artifact has no rawScriptSpans key: " + artifact);
        assertEquals(expected, m.group(1).replaceAll("\\s", ""));
    }

    private static String compileArtifact(String source) throws IOException {
        Path dir = Files.createTempDirectory("n151-raw-spans");
        Path src = dir.resolve("WithAsm.runar.ts");
        Path out = dir.resolve("artifact.json");
        Files.writeString(src, source);
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream outPs = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        PrintStream errPs = new PrintStream(stderr, true, StandardCharsets.UTF_8);
        int exit = new Cli(outPs, errPs).run(
            new String[] {"--source", src.toString(), "--emit-artifact", out.toString()});
        assertEquals(0, exit, "--emit-artifact failed: " + stderr.toString(StandardCharsets.UTF_8));
        return Files.readString(out);
    }
}
