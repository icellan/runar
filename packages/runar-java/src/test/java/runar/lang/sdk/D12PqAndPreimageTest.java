package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import runar.compiler.Cli;

/**
 * D12 PQ-F1 and D2.
 *
 * <p>PQ-F1: a wrong-length WOTS+ / SLH-DSA public key deployed silently and
 * the output refused the owner's valid signature forever. {@code
 * RunarContract} now refuses, at construction, a constructor arg loaded
 * straight into a PQ verifier's pk operand when its length is wrong.
 *
 * <p>D2: the SDK ANF interpreter answered extractLocktime / extractSequence /
 * extractOutpoint with dummies (0 / 0xfffffffe / 36 zero bytes); the call path
 * now hands it the real values of the transaction it builds.
 *
 * <p>Proves: WOTS (64) and SLH-DSA 128s (32) lengths enforced on artifacts
 * carrying ANF; the committed state equals the call options' locktime, the
 * input sequence resolveInputSequence puts on input 0, and the spent outpoint.
 * Does not prove: stateless artifacts (no ANF), hash-committed keys, script
 * acceptance (Java ships no ScriptVM).
 */
class D12PqAndPreimageTest {

    private static RunarArtifact compile(String name, String src) throws Exception {
        Path dir = Files.createTempDirectory("d12-java");
        Path file = dir.resolve(name + ".runar.ts");
        Path out = dir.resolve("artifact.json");
        try {
            Files.writeString(file, src);
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int exit = new Cli(
                new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8)
            ).run(new String[] {"--source", file.toString(), "--emit-artifact", out.toString()});
            assertEquals(0, exit, stderr.toString(StandardCharsets.UTF_8));
            return RunarArtifact.fromJson(Files.readString(out));
        } finally {
            Files.deleteIfExists(out);
            Files.deleteIfExists(file);
            Files.deleteIfExists(dir);
        }
    }

    private static String compileJson(String name, String src) throws Exception {
        Path dir = Files.createTempDirectory("pq-f1-java");
        Path file = dir.resolve(name + ".runar.ts");
        Path out = dir.resolve("artifact.json");
        Files.writeString(file, src);
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        int exit = new Cli(
            new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
            new PrintStream(stderr, true, StandardCharsets.UTF_8)
        ).run(new String[] {"--source", file.toString(), "--emit-artifact", out.toString()});
        assertEquals(0, exit, stderr.toString(StandardCharsets.UTF_8));
        return Files.readString(out);
    }

    /**
     * PQ-F1 (artifact field): the check reads {@code pqPubKeyParams}, so a
     * STATELESS artifact (no ANF) is refused too, with the message shared by
     * all seven SDKs; an older stateful artifact without the field falls back
     * to the ANF walk.
     */
    @Test
    void statelessArtifactCheckedFromPqPubKeyParams() throws Exception {
        RunarArtifact art = RunarArtifact.fromJson(compileJson("SW", String.join("\n",
            "import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';",
            "class SW extends SmartContract {",
            "  readonly pk: ByteString;",
            "  constructor(pk: ByteString) { super(pk); this.pk = pk; }",
            "  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }",
            "}", "")));
        assertEquals(null, art.anf());
        assertEquals(1, art.pqPubKeyParams().size());
        InvalidConstructorArgException e = assertThrows(InvalidConstructorArgException.class,
            () -> new RunarContract(art, List.of("ab".repeat(32))));
        assertEquals("RunarContract: constructor arg 'pk' is the verifyWOTS public key and must be exactly 64 bytes, got 32. "
            + "A locking script built from it would refuse every valid signature, so the output could never be spent (PQ-F1)",
            e.getMessage());
        for (int bad : new int[] {0, 63, 65}) {
            assertThrows(InvalidConstructorArgException.class, () -> new RunarContract(art, List.of("ab".repeat(bad))));
        }
        assertDoesNotThrow(() -> new RunarContract(art, List.of("ab".repeat(64))));

        String legacyJson = compileJson("LW", String.join("\n",
            "import { StatefulSmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';",
            "class LW extends StatefulSmartContract {",
            "  readonly pk: ByteString;",
            "  n: bigint;",
            "  constructor(pk: ByteString, n: bigint) { super(pk, n); this.pk = pk; this.n = n; }",
            "  public spend(msg: ByteString, sig: ByteString) { const k = this.pk; assert(verifyWOTS(msg, sig, k)); this.n = this.n + 1n; }",
            "}", ""));
        String stripped = legacyJson.replaceFirst("\\s*\"pqPubKeyParams\":\\s*\\[[^\\]]*],", "");
        assertEquals(false, stripped.contains("pqPubKeyParams"));
        RunarArtifact legacy = RunarArtifact.fromJson(stripped);
        assertThrows(InvalidConstructorArgException.class,
            () -> new RunarContract(legacy, List.of("ab".repeat(32), BigInteger.ZERO)));
        assertDoesNotThrow(() -> new RunarContract(legacy, List.of("ab".repeat(64), BigInteger.ZERO)));
    }

    private static String pqSource(String verify) {
        return String.join("\n",
            "import { StatefulSmartContract, ByteString, assert, " + verify + " } from 'runar-lang';",
            "class Pq extends StatefulSmartContract {",
            "  readonly pk: ByteString;",
            "  n: bigint;",
            "  constructor(pk: ByteString, n: bigint) { super(pk, n); this.pk = pk; this.n = n; }",
            "  public spend(msg: ByteString, sig: ByteString) {",
            "    assert(" + verify + "(msg, sig, this.pk));",
            "    this.n = this.n + 1n;",
            "  }",
            "}", "");
    }

    @Test
    void pqPubkeyLengthEnforced() throws Exception {
        Object[][] cases = {{"verifyWOTS", 64}, {"verifySLHDSA_SHA2_128s", 32}};
        for (Object[] c : cases) {
            String verify = (String) c[0];
            int want = (Integer) c[1];
            RunarArtifact art = compile("Pq", pqSource(verify));
            assertDoesNotThrow(() -> new RunarContract(art, List.of("ab".repeat(want), BigInteger.ZERO)));
            for (int bad : new int[] {0, want - 1, want + 1, want / 2, want * 2}) {
                assertThrows(InvalidConstructorArgException.class,
                    () -> new RunarContract(art, List.of("ab".repeat(bad), BigInteger.ZERO)), verify + " len " + bad);
            }
        }
    }

    private static final String PROBE = String.join("\n",
        "import { StatefulSmartContract, ByteString, extractLocktime, extractSequence, extractOutpoint } from 'runar-lang';",
        "class Probe extends StatefulSmartContract {",
        "  lt: bigint;",
        "  sq: bigint;",
        "  op: ByteString;",
        "  constructor(lt: bigint, sq: bigint, op: ByteString) { super(lt, sq, op); this.lt = lt; this.sq = sq; this.op = op; }",
        "  public probe() {",
        "    this.lt = extractLocktime(this.txPreimage);",
        "    this.sq = extractSequence(this.txPreimage);",
        "    this.op = extractOutpoint(this.txPreimage);",
        "  }",
        "}", "");

    @Test
    void extractorsSeeTheRealCallTransaction() throws Exception {
        RunarArtifact art = compile("Probe", PROBE);
        for (Integer locktime : new Integer[] {null, 500}) {
            MockProvider provider = new MockProvider();
            LocalSigner signer = new LocalSigner("11".repeat(32));
            provider.addUtxo(signer.address(),
                new UTXO("aa".repeat(32), 0, 5_000_000L, ScriptUtils.buildP2PKHScript(signer.address())));
            RunarContract c = new RunarContract(art, List.of(BigInteger.valueOf(7), BigInteger.valueOf(7), "00"));
            c.deploy(provider, signer, 50_000L, signer.address());
            UTXO spent = c.currentUtxo();
            CallOptions opts = new CallOptions(null, null, null).withLocktime(locktime);
            c.callWithOptions("probe", List.of(), opts, provider, signer);
            StringBuilder wantOp = new StringBuilder();
            for (int i = 31; i >= 0; i--) wantOp.append(spent.txid(), i * 2, i * 2 + 2);
            wantOp.append(String.format("%02x%02x%02x%02x", spent.outputIndex() & 0xff,
                (spent.outputIndex() >>> 8) & 0xff, (spent.outputIndex() >>> 16) & 0xff, (spent.outputIndex() >>> 24) & 0xff));
            assertEquals(BigInteger.valueOf(locktime == null ? 0 : locktime), c.state("lt"), "lt @ " + locktime);
            assertEquals(BigInteger.valueOf(locktime == null ? 0xffffffffL : 0xfffffffeL), c.state("sq"), "sq @ " + locktime);
            assertEquals(wantOp.toString(), c.state("op"), "op @ " + locktime);
        }
    }
}
