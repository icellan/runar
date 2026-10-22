package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-314: the Java tier's builtin registry did not know the three BN254 pairing
 * builtins ({@code bn254Pairing}, {@code bn254MultiPairing3},
 * {@code bn254MultiPairing4}), although {@code BuiltinArity} and
 * {@code codegen/Bn254} list them. The validator refused them as "unknown
 * function", so {@code --parse-only} failed on every surface of the
 * {@code bn254-pairing} conformance fixture and broke frontend parity.
 *
 * <p>Proves: each of the three calls passes parse + validate, and a full
 * compile then stops at the documented Go-only codegen refusal rather than at
 * the validator.
 *
 * <p>Does NOT prove: anything about pairing codegen, which the Java tier
 * deliberately does not carry (BN254 is Go-only by project policy).
 */
class N314Bn254PairingBuiltinsTest {

    @TempDir
    Path tmp;

    private static String pair(int i) {
        return "p" + i + ": Point, q" + i + "x0: bigint, q" + i + "x1: bigint, q" + i + "y0: bigint, q" + i + "y1: bigint";
    }

    private static String pairArgs(int i) {
        return "p" + i + ", q" + i + "x0, q" + i + "x1, q" + i + "y0, q" + i + "y1";
    }

    private static String contract(String params, String body) {
        return "import { SmartContract, assert } from 'runar-lang';\n"
            + "import type { Point } from 'runar-lang';\n"
            + "class P extends SmartContract {\n"
            + "  constructor() { super(); }\n"
            + "  public verify(" + params + ") {\n"
            + "    " + body + "\n"
            + "  }\n"
            + "}\n";
    }

    private static String fp12Params() {
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < 12; k++) sb.append(", f").append(k).append(": bigint");
        return sb.toString();
    }

    private static String fp12Args() {
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < 12; k++) sb.append(", f").append(k);
        return sb.toString();
    }

    @Test
    void bn254PairingIsAKnownBuiltin() throws IOException {
        assertValidatesThenRefusedAtCodegen("bn254Pairing", contract(
            pair(1) + ", e: bigint",
            "assert(bn254Pairing(" + pairArgs(1) + ") === e);"));
    }

    @Test
    void bn254MultiPairing3IsAKnownBuiltin() throws IOException {
        assertValidatesThenRefusedAtCodegen("bn254MultiPairing3", contract(
            pair(1) + ", " + pair(2) + ", " + pair(3) + fp12Params(),
            "assert(bn254MultiPairing3(" + pairArgs(1) + ", " + pairArgs(2) + ", " + pairArgs(3) + fp12Args() + "));"));
    }

    @Test
    void bn254MultiPairing4IsAKnownBuiltin() throws IOException {
        assertValidatesThenRefusedAtCodegen("bn254MultiPairing4", contract(
            pair(1) + ", " + pair(2) + ", " + pair(3) + ", " + pair(4),
            "assert(bn254MultiPairing4(" + pairArgs(1) + ", " + pairArgs(2) + ", " + pairArgs(3) + ", " + pairArgs(4) + "));"));
    }

    @Test
    void everySurfaceOfTheConformanceFixtureParses() throws IOException {
        Path dir = repo().resolve("conformance/tests/bn254-pairing");
        for (String ext : new String[] {"ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"}) {
            Path src = dir.resolve("Bn254Pairing.runar." + ext);
            Result r = runCli("--source", src.toString(), "--parse-only");
            assertEquals(0, r.exit, ext + ": --parse-only failed: " + r.stderr);
        }
    }

    private void assertValidatesThenRefusedAtCodegen(String builtin, String source) throws IOException {
        Path file = tmp.resolve("P.runar.ts");
        Files.writeString(file, source, StandardCharsets.UTF_8);

        Result parse = runCli("--source", file.toString(), "--parse-only");
        assertEquals(0, parse.exit, builtin + ": --parse-only should accept it: " + parse.stderr);

        Result compile = runCli("--source", file.toString(), "--hex");
        assertNotEquals(0, compile.exit, builtin + ": Java must not emit BN254 pairing codegen");
        assertFalse(compile.stderr.contains("unknown function"),
            builtin + ": refused by the validator instead of codegen: " + compile.stderr);
        assertTrue(compile.stderr.contains("builtin '" + builtin + "' belongs to the BN254/Groth16 family which is Go-only"),
            builtin + ": expected the documented Go-only codegen refusal, got: " + compile.stderr);
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
