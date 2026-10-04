package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import runar.compiler.passes.AnfLoader;

/**
 * F-038 / F-065 / F-066 / F-070 / F-088 — an {@code --emit-ir} -> {@code --ir}
 * round trip must reproduce the {@code --source} artifact's {@code parentClass}
 * and {@code abi.methods[].sigHashType}.
 *
 * <p>Both lived on the in-memory ANF only ({@code AnfMethod.sighashType} was
 * {@code @JsonSkip}; {@code AnfProgram} had no parentClass and
 * {@code Cli#compileIr} passed {@code null}), so the IR-path artifact had no
 * parentClass — the SDK then skips the issue-#44 subscript trim for a
 * StatefulSmartContract with zero mutable fields — and no sigHashType — the
 * SDK then builds an ALL|FORKID preimage for a covenant asserting another mode.
 *
 * <p>What this proves: the emitted IR carries both keys (and omits
 * sigHashType for the default mode); the IR-path artifact's parentClass and
 * method sigHashType equal the source path's; the loader refuses a malformed
 * value of either key with the diagnostic shared by all seven tiers.
 *
 * <p>What it does not prove: that an SDK spends the resulting artifact, or the
 * other six tiers (conformance/ir-roundtrip does both), or FixedArray state
 * regrouping, which the Java artifact writer still does not do on either path.
 */
class F038IrRoundTripTest {

    @Test
    void statefulZeroMutableKeepsParentClassThroughTheIrPath() throws IOException {
        Path src = repo().resolve("examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts");
        RoundTrip rt = roundTrip(src);
        assertEquals("StatefulSmartContract", stringField(rt.ir, "parentClass"));
        assertTrue(!rt.ir.contains("\"sigHashType\""), "default mode must not be emitted: " + rt.ir);
        assertEquals("StatefulSmartContract", stringField(rt.direct, "parentClass"));
        assertEquals(stringField(rt.direct, "parentClass"), stringField(rt.viaIr, "parentClass"));
        assertEquals(stringField(rt.direct, "script"), stringField(rt.viaIr, "script"));
    }

    @Test
    void nonDefaultSighashSurvivesTheIrPath() throws IOException {
        Path src = repo().resolve("conformance/ir-roundtrip/SighashSingle.runar.ts");
        RoundTrip rt = roundTrip(src);
        assertEquals("SmartContract", stringField(rt.ir, "parentClass"));
        assertEquals(67, intField(rt.ir, "sigHashType"));
        assertEquals(67, intField(rt.direct, "sigHashType"));
        assertEquals(67, intField(rt.viaIr, "sigHashType"));
        assertEquals("SmartContract", stringField(rt.viaIr, "parentClass"));
        assertEquals(stringField(rt.direct, "script"), stringField(rt.viaIr, "script"));
    }

    @Test
    void statefulNonDefaultSighashSurvivesTheIrPath() throws IOException {
        Path src = repo().resolve("conformance/ir-roundtrip/SighashCounter.runar.ts");
        RoundTrip rt = roundTrip(src);
        assertEquals(193, intField(rt.ir, "sigHashType"));
        assertEquals(193, intField(rt.viaIr, "sigHashType"));
        assertEquals("StatefulSmartContract", stringField(rt.viaIr, "parentClass"));
    }

    // -- loader validation (shared diagnostics) -------------------------------

    private static final String CONTROL = """
        {"contractName":"X","properties":[{"name":"pk","type":"PubKey","readonly":true}],"methods":[
          {"name":"unlock","isPublic":true,"params":[{"name":"sig","type":"Sig"}],"body":[
            {"name":"t0","value":{"kind":"load_param","name":"sig"}},
            {"name":"t1","value":{"kind":"load_prop","name":"pk"}},
            {"name":"t2","value":{"kind":"call","func":"checkSig","args":["t0","t1"]}},
            {"name":"t3","value":{"kind":"assert","value":"t2"}}
          ]}
        ]}
        """;

    private static String withProgramKey(String kv) {
        return CONTROL.replaceFirst("\\{\"contractName\":\"X\",", "{\"contractName\":\"X\"," + kv + ",");
    }

    private static String withMethodKey(String kv) {
        return CONTROL.replaceFirst("\"isPublic\":true,", "\"isPublic\":true," + kv + ",");
    }

    private static void assertRefused(String json, String message) {
        RuntimeException ex = org.junit.jupiter.api.Assertions.assertThrows(
            RuntimeException.class, () -> AnfLoader.parse(json));
        assertEquals(message, ex.getMessage());
    }

    @Test
    void loaderReadsAndValidatesBothKeys() {
        assertEquals("StatefulSmartContract",
            AnfLoader.parse(withProgramKey("\"parentClass\":\"StatefulSmartContract\"")).parentClass());
        assertEquals(Integer.valueOf(0x43),
            AnfLoader.parse(withMethodKey("\"sigHashType\":67")).methods().get(0).sighashType());
        assertEquals(null, AnfLoader.parse(CONTROL).parentClass());
        assertEquals(null, AnfLoader.parse(withProgramKey("\"parentClass\":null")).parentClass());

        assertRefused(withProgramKey("\"parentClass\":7"),
            "IR validation: parentClass must be a string, got number");
        assertRefused(withProgramKey("\"parentClass\":\"Contract\""),
            "IR validation: parentClass must be one of SmartContract, StatefulSmartContract, UnsafeSmartContract, got Contract");
        assertRefused(withMethodKey("\"sigHashType\":\"0x43\""),
            "IR validation: methods[0].sigHashType must be an integer, got string");
        assertRefused(withMethodKey("\"sigHashType\":3"),
            "IR validation: methods[0].sigHashType must be one of 65, 66, 67, 193, 194, 195, got 3");
    }

    // -- helpers ---------------------------------------------------------------

    private record RoundTrip(String direct, String ir, String viaIr) {}

    private static RoundTrip roundTrip(Path src) throws IOException {
        Path dir = Files.createTempDirectory("f038-java");
        try {
            Path direct = dir.resolve("direct.json");
            Path irFile = dir.resolve("p.ir.json");
            Path viaIr = dir.resolve("via-ir.json");
            Result a = runCli("--source", src.toString(), "--emit-artifact", direct.toString());
            assertEquals(0, a.exit, a.stderr);
            Result b = runCli("--source", src.toString(), "--emit-ir");
            assertEquals(0, b.exit, b.stderr);
            Files.writeString(irFile, b.stdout);
            Result c = runCli("--ir", irFile.toString(), "--emit-artifact", viaIr.toString());
            assertEquals(0, c.exit, c.stderr);
            return new RoundTrip(Files.readString(direct), b.stdout, Files.readString(viaIr));
        } finally {
            for (String f : new String[] {"direct.json", "p.ir.json", "via-ir.json"}) {
                Files.deleteIfExists(dir.resolve(f));
            }
            Files.deleteIfExists(dir);
        }
    }

    private static String stringField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static Integer intField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        return m.find() ? Integer.valueOf(m.group(1)) : null;
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
        return new Result(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }
}
