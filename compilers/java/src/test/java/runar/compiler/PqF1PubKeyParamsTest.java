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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * PQ-F1: the {@code --emit-artifact} JSON lists every constructor param passed
 * directly as the public key of verifyWOTS / verifySLHDSA_SHA2_*, with the
 * exact byte length that verifier needs, so every SDK can refuse a
 * wrong-length key before deploying (stateless artifacts carry no ANF).
 *
 * <p>Proves: the exact {@code pqPubKeyParams} text (key order included, after
 * stripping whitespace) for a stateless WOTS contract, an SLH-DSA-192f
 * contract, and a key behind a local alias plus a key read in a private
 * helper; absent for a key passed as a method argument. Does NOT prove
 * cross-tier equality ({@code conformance/negatives/artifact-flag-parity.test.ts}).
 */
class PqF1PubKeyParamsTest {

    @Test
    void statelessWots() throws IOException {
        assertPq("[{\"index\":0,\"name\":\"pk\",\"scheme\":\"verifyWOTS\",\"length\":64}]",
            "import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';\n"
            + "class C extends SmartContract {\n"
            + "  readonly pk: ByteString;\n"
            + "  constructor(pk: ByteString) { super(pk); this.pk = pk; }\n"
            + "  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }\n"
            + "}\n");
    }

    @Test
    void slh192f() throws IOException {
        assertPq("[{\"index\":0,\"name\":\"pk\",\"scheme\":\"verifySLHDSA_SHA2_192f\",\"length\":48}]",
            "import { SmartContract, ByteString, assert, verifySLHDSA_SHA2_192f } from 'runar-lang';\n"
            + "class C extends SmartContract {\n"
            + "  readonly pk: ByteString;\n"
            + "  constructor(pk: ByteString) { super(pk); this.pk = pk; }\n"
            + "  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_192f(msg, sig, this.pk)); }\n"
            + "}\n");
    }

    @Test
    void aliasAndHelper() throws IOException {
        assertPq("[{\"index\":1,\"name\":\"a\",\"scheme\":\"verifyWOTS\",\"length\":64},"
                + "{\"index\":2,\"name\":\"b\",\"scheme\":\"verifyWOTS\",\"length\":64}]",
            "import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';\n"
            + "class C extends SmartContract {\n"
            + "  readonly tag: bigint;\n"
            + "  readonly a: ByteString;\n"
            + "  readonly b: ByteString;\n"
            + "  constructor(tag: bigint, a: ByteString, b: ByteString) { super(tag, a, b); this.tag = tag; this.a = a; this.b = b; }\n"
            + "  private checkB(msg: ByteString, sig: ByteString): boolean { return verifyWOTS(msg, sig, this.b); }\n"
            + "  public spend(msg: ByteString, sig: ByteString, sig2: ByteString) {\n"
            + "    assert(this.checkB(msg, sig2));\n"
            + "    const k = this.a;\n"
            + "    assert(verifyWOTS(msg, sig, k));\n"
            + "    assert(this.tag > 0n);\n"
            + "  }\n"
            + "}\n");
    }

    @Test
    void keyAsMethodArgIsAbsent() throws IOException {
        String artifact = compileArtifact(
            "import { SmartContract, ByteString, Sha256, assert, sha256, verifyWOTS } from 'runar-lang';\n"
            + "class C extends SmartContract {\n"
            + "  readonly h: Sha256;\n"
            + "  constructor(h: Sha256) { super(h); this.h = h; }\n"
            + "  public spend(msg: ByteString, sig: ByteString, pk: ByteString) { assert(sha256(pk) === this.h); assert(verifyWOTS(msg, sig, pk)); }\n"
            + "}\n");
        assertFalse(artifact.contains("\"pqPubKeyParams\""), artifact);
    }

    private static void assertPq(String expected, String source) throws IOException {
        String artifact = compileArtifact(source);
        Matcher m = Pattern.compile("\"pqPubKeyParams\"\\s*:\\s*(\\[[^\\]]*])").matcher(artifact);
        assertTrue(m.find(), "artifact has no pqPubKeyParams key");
        assertEquals(expected, m.group(1).replaceAll("\\s", ""));
    }

    private static String compileArtifact(String source) throws IOException {
        Path dir = Files.createTempDirectory("pq-f1");
        Path src = dir.resolve("C.runar.ts");
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
