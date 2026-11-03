package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ZigParser;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.PropertyNode;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-090: the Java tier's {@code .runar.zig} parser left
 * {@code runar.hexToBytes("<hex>")} as an ordinary call, so a property
 * initialised with it was refused ("initializer must be a literal value") and
 * the checked-in examples/zig/tic-tac-toe/TicTacToe.runar.zig did not compile.
 *
 * <p>Proves: {@code runar.hexToBytes("<hex>")} lowers to a ByteStringLiteral
 * holding the hex verbatim (as 01-parse-zig.ts, the Zig tier and Python do); a
 * non-literal argument is refused with TS's diagnostic; the Zig-surface
 * TicTacToe compiles to the same script as the TS-surface TicTacToe in this
 * tier.
 *
 * <p>Does NOT prove: identity with the TS compiler (pinned by the
 * hex-to-bytes-initializer conformance fixture and the remediation sweep), or
 * that the hex payload is well-formed (TS does not check it either).
 */
class N090ZigHexToBytesTest {

    private static final String SOURCE = """
        const runar = @import("runar");

        pub const H = struct {
            pub const Contract = runar.SmartContract;

            prefix: runar.Readonly(runar.ByteString) = runar.hexToBytes("1976a914"),
            x: runar.ByteString,

            pub fn init(x: runar.ByteString) H {
                return .{ .x = x };
            }

            pub fn verify(self: *const H, b: runar.ByteString) void {
                runar.assert(runar.bytesEq(runar.cat(self.prefix, self.x), b));
            }
        };
        """;

    @Test
    void hexToBytesInitializerIsAByteStringLiteral() throws ZigParser.ParseException {
        ContractNode c = ZigParser.parse(SOURCE, "H.runar.zig");
        PropertyNode prefix = c.properties().stream()
            .filter(p -> p.name().equals("prefix")).findFirst().orElseThrow();
        assertInstanceOf(ByteStringLiteral.class, prefix.initializer(),
            "expected a ByteStringLiteral initializer, got " + prefix.initializer());
        assertEquals("1976a914", ((ByteStringLiteral) prefix.initializer()).value());
    }

    @Test
    void hexToBytesNonLiteralArgumentIsRefused() {
        String src = SOURCE.replace("runar.hexToBytes(\"1976a914\")", "runar.hexToBytes(x)");
        ZigParser.ParseException e = assertThrows(ZigParser.ParseException.class,
            () -> ZigParser.parse(src, "H.runar.zig"));
        assertTrue(e.getMessage().contains("runar.hexToBytes expects a string literal argument"),
            "expected TS's diagnostic, got: " + e.getMessage());
    }

    @Test
    void ticTacToeZigExampleCompilesLikeTheTsSurface() throws IOException {
        Path examples = repo().resolve("examples");
        Result zig = runCli("--source",
            examples.resolve("zig/tic-tac-toe/TicTacToe.runar.zig").toString(), "--hex");
        assertEquals(0, zig.exit, "TicTacToe.runar.zig failed to compile: " + zig.stderr);
        Result ts = runCli("--source",
            examples.resolve("ts/tic-tac-toe/TicTacToe.runar.ts").toString(), "--hex");
        assertEquals(0, ts.exit, "TicTacToe.runar.ts failed to compile: " + ts.stderr);
        assertFalse(zig.stdout.trim().isEmpty());
        assertEquals(ts.stdout.trim(), zig.stdout.trim(),
            "Zig-surface TicTacToe differs from the TS surface");
    }

    private static Path repo() throws IOException {
        for (Path p = Paths.get("").toAbsolutePath(); p != null; p = p.getParent()) {
            if (Files.isDirectory(p.resolve("conformance").resolve("tests"))) return p;
        }
        throw new IOException("repo root not found");
    }

    private record Result(int exit, String stdout, String stderr) {}

    private static Result runCli(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, StandardCharsets.UTF_8);
        PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8);
        int exit = new Cli(o, e).run(args);
        o.flush();
        e.flush();
        return new Result(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }
}
