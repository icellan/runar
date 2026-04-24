package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CliTest {

    @Test
    void versionFlagPrintsVersionAndExitsZero() {
        Result r = run("--version");
        assertEquals(0, r.exit);
        assertEquals("runar-java " + Version.VALUE, r.stdout.trim());
        assertEquals("", r.stderr.trim());
    }

    @Test
    void helpFlagPrintsUsageAndExitsZero() {
        Result r = run("--help");
        assertEquals(0, r.exit);
        assertTrue(r.stdout.contains("--source"), "usage should mention --source");
        assertTrue(r.stdout.contains("--hex"), "usage should mention --hex");
    }

    @Test
    void noArgsPrintsUsageAndExitsNonZero() {
        Result r = run();
        assertEquals(2, r.exit);
    }

    @Test
    void unknownFlagExitsTwo() {
        Result r = run("--bogus");
        assertEquals(2, r.exit);
        assertTrue(r.stderr.contains("unknown flag"), "stderr should explain the unknown flag");
    }

    @Test
    void emitIrProducesCanonicalJson() throws Exception {
        String src = """
            package runar.examples.p2pkh;

            import runar.lang.*;

            public class P2PKH extends SmartContract {
                @Readonly Addr pubKeyHash;

                public P2PKH(Addr pubKeyHash) {
                    super(pubKeyHash);
                    this.pubKeyHash = pubKeyHash;
                }

                @Public
                public void unlock(Sig sig, PubKey pubKey) {
                    assertThat(hash160(pubKey).equals(pubKeyHash));
                    assertThat(checkSig(sig, pubKey));
                }
            }
            """;
        Path tmp = Files.createTempFile("P2PKH", ".runar.java");
        try {
            Files.writeString(tmp, src);
            Result r = run("--source", tmp.toString(), "--emit-ir", "--disable-constant-folding");
            assertEquals(0, r.exit, "stderr: " + r.stderr);
            assertNotEquals("", r.stdout.trim());
            assertTrue(r.stdout.contains("\"contractName\":\"P2PKH\""), r.stdout);
            assertTrue(r.stdout.contains("\"kind\":\"assert\""), r.stdout);
            assertTrue(r.stdout.contains("\"func\":\"hash160\""), r.stdout);
            assertTrue(r.stdout.contains("\"func\":\"checkSig\""), r.stdout);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    @Test
    void hexFlagStillNotImplemented() throws Exception {
        // Stack lowering + emit land in M5. Until then, --hex must exit
        // non-zero with an explicit "not implemented" message so the
        // conformance runner can distinguish "not yet" from "broken".
        String src = """
            package runar.examples.p2pkh;

            import runar.lang.*;

            public class P2PKH extends SmartContract {
                @Readonly Addr pubKeyHash;

                public P2PKH(Addr pubKeyHash) {
                    super(pubKeyHash);
                    this.pubKeyHash = pubKeyHash;
                }

                @Public
                public void unlock(Sig sig, PubKey pubKey) {
                    assertThat(hash160(pubKey).equals(pubKeyHash));
                    assertThat(checkSig(sig, pubKey));
                }
            }
            """;
        Path tmp = Files.createTempFile("P2PKH", ".runar.java");
        try {
            Files.writeString(tmp, src);
            Result r = run("--source", tmp.toString(), "--hex", "--disable-constant-folding");
            assertEquals(64, r.exit);
            assertTrue(r.stderr.contains("not yet implemented"),
                "stderr should mention the stub state: " + r.stderr);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    @Test
    void irFlagStillNotImplemented() {
        // --ir (reading pre-generated ANF JSON) is an M5 concern — stack
        // lowering + emit on IR input arrives alongside --hex.
        Result r = run("--ir", "/nonexistent.json", "--hex");
        assertEquals(64, r.exit);
        assertTrue(r.stderr.contains("not yet implemented"),
            "stderr should mention the stub state: " + r.stderr);
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
            stderr.toString(StandardCharsets.UTF_8)
        );
    }
}
