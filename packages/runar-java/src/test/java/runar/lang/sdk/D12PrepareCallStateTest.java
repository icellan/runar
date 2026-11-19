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

import org.junit.jupiter.api.Test;
import runar.compiler.Cli;

/**
 * D12 SDK-F1/F2: {@code prepareCall} must never leave the tracked state
 * changed. It restored on a prepare error but advanced the state on success,
 * so an abandoned PreparedCall left state at n+1 while the chain was at n, and
 * a second prepare snapshotted the first one's post-state as its
 * {@code stateBefore}. Semantics now (all tiers): the post-state travels in the
 * PreparedCall and {@code finalizeCall} commits it only after a successful
 * broadcast.
 *
 * <p>Proves: a {@code getFeeRate} failure inside prepareCall and an abandoned
 * PreparedCall leave state and UTXO untouched; prepare A, prepare B, finalize
 * A ok, finalize B refused leaves A's committed state.
 * Does not prove: script acceptance (Java ships no ScriptVM).
 */
class D12PrepareCallStateTest {

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

    private static final class FlakyProvider implements Provider {
        final MockProvider inner = new MockProvider();
        boolean refuse;
        boolean failFeeRate;

        @Override public List<UTXO> listUtxos(String address) { return inner.listUtxos(address); }
        @Override public UTXO getUtxo(String txid, int vout) { return inner.getUtxo(txid, vout); }
        @Override public long getFeeRate() {
            if (failFeeRate) {
                failFeeRate = false;
                throw new IllegalStateException("HTTP 503");
            }
            return inner.getFeeRate();
        }
        @Override public String broadcastRaw(String txHex) {
            if (refuse) throw new IllegalStateException("node refused the transaction");
            return inner.broadcastRaw(txHex);
        }
    }

    private static final LocalSigner SIGNER = new LocalSigner("11".repeat(32));

    private static RunarArtifact compile() throws Exception {
        Path dir = Files.createTempDirectory("d12-prepare-java");
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

    private static RunarContract deployGate(FlakyProvider provider) throws Exception {
        provider.inner.addUtxo(SIGNER.address(),
            new UTXO("aa".repeat(32), 0, 5_000_000L, ScriptUtils.buildP2PKHScript(SIGNER.address())));
        RunarContract contract = new RunarContract(compile(), List.of(BigInteger.ZERO));
        contract.deploy(provider, SIGNER, 50_000L, SIGNER.address());
        return contract;
    }

    private static final List<Object> SEVEN = List.of(BigInteger.valueOf(7));

    @Test
    void prepareErrorLeavesStateUntouched() throws Exception {
        FlakyProvider provider = new FlakyProvider();
        RunarContract contract = deployGate(provider);
        UTXO utxoBefore = contract.currentUtxo();
        provider.failFeeRate = true;
        assertThrows(RuntimeException.class, () -> contract.call("bump", SEVEN, null, provider, SIGNER));
        assertEquals(BigInteger.ZERO, contract.state("n"));
        assertEquals(utxoBefore, contract.currentUtxo());
        contract.call("bump", SEVEN, null, provider, SIGNER);
        assertEquals(BigInteger.ONE, contract.state("n"));
    }

    @Test
    void abandonedPreparedCallLeavesStateUntouched() throws Exception {
        FlakyProvider provider = new FlakyProvider();
        RunarContract contract = deployGate(provider);
        contract.prepareCall("bump", SEVEN, provider, SIGNER);
        assertEquals(BigInteger.ZERO, contract.state("n"));
        contract.call("bump", SEVEN, null, provider, SIGNER);
        assertEquals(BigInteger.ONE, contract.state("n"));
    }

    @Test
    void supersededPrepareFailedFinalizeKeepsCommittedState() throws Exception {
        FlakyProvider provider = new FlakyProvider();
        RunarContract contract = deployGate(provider);
        PreparedCall a = contract.prepareCall("bump", SEVEN, provider, SIGNER);
        PreparedCall b = contract.prepareCall("bump", SEVEN, provider, SIGNER);
        assertEquals(BigInteger.ZERO, contract.state("n"));
        contract.finalizeCall(a, List.of(), provider);
        assertEquals(BigInteger.ONE, contract.state("n"));
        UTXO utxoAfter = contract.currentUtxo();
        provider.refuse = true;
        assertThrows(RuntimeException.class, () -> contract.finalizeCall(b, List.of(), provider));
        assertEquals(BigInteger.ONE, contract.state("n"));
        assertEquals(utxoAfter, contract.currentUtxo());
    }
}
