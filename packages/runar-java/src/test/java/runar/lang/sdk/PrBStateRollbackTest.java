package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import runar.compiler.Cli;

/**
 * The call path advances the contract's local state to the post-call state
 * BEFORE the broadcast. When the broadcast was refused nothing put it back, so
 * the next call was built from a state the chain never reached (same bug as
 * the TS SDK, packages/runar-sdk/src/__tests__/pr-b-state-rollback.test.ts).
 *
 * <p>Java ships no ScriptVM, so MockProvider cannot refuse the failing
 * covenant on its own; the refusal comes from a provider that delegates to a
 * MockProvider but whose broadcast throws while {@code refuse} is set, like a
 * node rejecting the transaction.
 *
 * <p>Proves: after a refused broadcast — via {@code call()} and via
 * {@code prepareCall()} + {@code finalizeCall()} — {@code state()} and
 * {@code currentUtxo()} equal their pre-call values, and an honest follow-up
 * call commits n = 1.
 */
class PrBStateRollbackTest {

    private static final String SRC = String.join("\n",
        "import { StatefulSmartContract, assert } from 'runar-lang';",
        "",
        "class Gate extends StatefulSmartContract {",
        "  n: bigint;",
        "  constructor(n: bigint) { super(n); this.n = n; }",
        "  public bump(k: bigint) {",
        "    assert(k === 7n);",
        "    this.n = this.n + 1n;",
        "  }",
        "}", "");

    /** Delegates to a MockProvider; broadcast throws while {@code refuse} is set. */
    private static final class RefusingProvider implements Provider {
        final MockProvider inner = new MockProvider();
        boolean refuse;

        @Override public List<UTXO> listUtxos(String address) { return inner.listUtxos(address); }
        @Override public UTXO getUtxo(String txid, int vout) { return inner.getUtxo(txid, vout); }
        @Override public long getFeeRate() { return inner.getFeeRate(); }
        @Override public String broadcastRaw(String txHex) {
            if (refuse) {
                throw new IllegalStateException("node refused the transaction (mandatory-script-verify-flag-failed)");
            }
            return inner.broadcastRaw(txHex);
        }
    }

    private static RunarArtifact compile() throws Exception {
        Path dir = Files.createTempDirectory("prb-rollback-java");
        Path src = dir.resolve("Gate.runar.ts");
        Path out = dir.resolve("artifact.json");
        try {
            Files.writeString(src, SRC);
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int exit = new Cli(
                new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8)
            ).run(new String[] {"--source", src.toString(), "--emit-artifact", out.toString()});
            assertEquals(0, exit, stderr.toString(StandardCharsets.UTF_8));
            return RunarArtifact.fromJson(Files.readString(out));
        } finally {
            Files.deleteIfExists(out);
            Files.deleteIfExists(src);
            Files.deleteIfExists(dir);
        }
    }

    private interface Bump {
        void run(RunarContract c, long k, RefusingProvider p, LocalSigner s);
    }

    private static final LocalSigner SIGNER = new LocalSigner("11".repeat(32));

    private static RunarContract deployGate(RefusingProvider provider) throws Exception {
        provider.inner.addUtxo(SIGNER.address(),
            new UTXO("aa".repeat(32), 0, 5_000_000L, ScriptUtils.buildP2PKHScript(SIGNER.address())));
        RunarContract contract = new RunarContract(compile(), List.of(BigInteger.ZERO));
        contract.deploy(provider, SIGNER, 50_000L, SIGNER.address());
        return contract;
    }

    private static void refusedThenHonest(Bump bump) throws Exception {
        LocalSigner signer = SIGNER;
        RefusingProvider provider = new RefusingProvider();
        RunarContract contract = deployGate(provider);
        Map<String, Object> stateBefore = Map.copyOf(contract.state());
        UTXO utxoBefore = contract.currentUtxo();

        provider.refuse = true;
        assertThrows(RuntimeException.class, () -> bump.run(contract, 8, provider, signer));
        assertEquals(stateBefore, Map.copyOf(contract.state()), "state must be unchanged after a refused broadcast");
        assertEquals(utxoBefore, contract.currentUtxo(), "tracked UTXO must be unchanged after a refused broadcast");

        provider.refuse = false;
        bump.run(contract, 7, provider, signer);
        assertEquals(BigInteger.ONE, contract.state("n"));
    }

    @Test
    void callRollsBackStateOnRefusedBroadcast() throws Exception {
        refusedThenHonest((c, k, p, s) ->
            c.call("bump", List.of(BigInteger.valueOf(k)), null, p, s));
    }

    /**
     * A PreparedCall whose broadcast was refused can be finalized again: the
     * retry commits the post-call state. A further finalize of the
     * now-committed PreparedCall that fails must not rewind the state the
     * chain reached.
     */
    @Test
    void retriedAndRepeatedFinalize() throws Exception {
        RefusingProvider provider = new RefusingProvider();
        RunarContract contract = deployGate(provider);
        UTXO utxoBefore = contract.currentUtxo();

        PreparedCall prepared = contract.prepareCall("bump", List.of(BigInteger.valueOf(7)), provider, SIGNER);
        provider.refuse = true;
        assertThrows(RuntimeException.class, () -> contract.finalizeCall(prepared, List.of(), provider));
        assertEquals(BigInteger.ZERO, contract.state("n"));
        assertEquals(utxoBefore, contract.currentUtxo());

        provider.refuse = false;
        contract.finalizeCall(prepared, List.of(), provider);
        assertEquals(BigInteger.ONE, contract.state("n"));
        UTXO utxoAfter = contract.currentUtxo();

        provider.refuse = true;
        assertThrows(RuntimeException.class, () -> contract.finalizeCall(prepared, List.of(), provider));
        assertEquals(BigInteger.ONE, contract.state("n"),
            "a refused repeat of a committed finalize must not rewind state");
        assertEquals(utxoAfter, contract.currentUtxo());
    }

    @Test
    void prepareFinalizeRollsBackStateOnRefusedBroadcast() throws Exception {
        refusedThenHonest((c, k, p, s) -> {
            PreparedCall prepared = c.prepareCall("bump", List.of(BigInteger.valueOf(k)), p, s);
            c.finalizeCall(prepared, List.of(), p);
        });
    }
}
