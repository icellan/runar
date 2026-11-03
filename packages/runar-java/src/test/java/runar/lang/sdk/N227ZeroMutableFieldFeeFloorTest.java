package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import runar.compiler.Cli;

/**
 * N-227 (port of sdk:ts N-085): a zero-mutable-field {@code StatefulSmartContract}
 * call underpays MockProvider's 100 sat/KB fee floor.
 *
 * <p>Unlike TS/Go/Rust/Python/Ruby (before each tier's N-227 fix), the Java
 * {@code RunarContract.call} entry point does NOT split "stateful" vs
 * "stateless" branches that size the fee/change from two DIFFERENT unlock
 * byte sizes. {@code callWithPushTx} / {@code layoutPushTx} routes a
 * zero-mutable-field StatefulSmartContract (which is {@code parentStateful}
 * but not {@code isStateful}, so {@code needsOpPushTx} is still true) through
 * the SAME unified flow a continuation-bearing stateful contract uses — and
 * crucially, {@code layoutPushTx} sizes its BIP-143 preimage PLACEHOLDER to
 * the real scriptCode length up front ({@code bip143PreimageLen(sighashSubscript)}),
 * rather than a generic short stub. So there is no undersized-placeholder gap
 * for this tier to fall into; this test pins that it never regresses one.
 *
 * <p>This fixture is {@code AllReadonlyCleanstack} (same contract N-085/N-227
 * use in every other tier), compiled on the fly via {@code runar.compiler.Cli
 * --source ... --emit-artifact ...} (mirrors {@code F038IrRoundTripTest}).
 *
 * <p>Proves: the Java SDK's {@code claim()} call on a zero-mutable-field
 * StatefulSmartContract broadcasts a tx whose actual fee (computed from the
 * REAL broadcast bytes this test parses itself via the package-private
 * {@link RawTxParser}: sum of known input satoshis minus sum of output
 * satoshis) meets the 100 sat/KB floor {@link MockProvider#getFeeRate()}
 * reports — i.e. this tier is ALREADY correct, no production fix was needed.
 *
 * <p>Does NOT prove: on-chain acceptance (Java ships no ScriptVM; the
 * off-chain {@code ContractSimulator} mentioned in CLAUDE.md is not used
 * here); nor anything about TypeScript (fixed separately, N-085), Go, Rust,
 * Python, Ruby or Zig, each a separate item slot; nor the merge
 * ({@code additionalContractInputs}) case for a zero-mutable-field contract,
 * which is out of scope here — Java already supports it (see
 * {@code AdditionalContractInputsTest}) via the same unified
 * {@code layoutPushTx} path with its own real per-input preimages, unlike
 * the five tiers this item adds a fail-closed guard to.
 */
class N227ZeroMutableFieldFeeFloorTest {

    private static final String PRIV =
        "0000000000000000000000000000000000000000000000000000000000000003";

    private static final String SRC = String.join("\n",
        "import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';",
        "",
        "class AllReadonlyCleanstack extends StatefulSmartContract {",
        "  readonly owner: PubKey;",
        "",
        "  constructor(owner: PubKey) {",
        "    super(owner);",
        "    this.owner = owner;",
        "  }",
        "",
        "  public claim(sig: Sig): void {",
        "    const ownerCopy = this.owner;",
        "    assert(checkSig(sig, this.owner));",
        "  }",
        "}", "");

    private static RunarArtifact compile() throws Exception {
        Path dir = Files.createTempDirectory("n227-java");
        Path src = dir.resolve("AllReadonlyCleanstack.runar.ts");
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

    @Test
    void claimOnAllReadonlyCleanstackPaysFeeFloor() throws Exception {
        RunarArtifact artifact = compile();

        // Sanity on the premise: zero mutable state fields, but still a real
        // StatefulSmartContract (auto-injects checkPreimage).
        assertEquals("StatefulSmartContract", artifact.parentClass());
        assertFalse(artifact.isStateful());
        assertTrue(artifact.stateFields() == null || artifact.stateFields().isEmpty());

        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider(); // broadcast validation default-on
        provider.addUtxo(signer.address(),
            new UTXO("aa".repeat(32), 0, 100_000L, ScriptUtils.buildP2PKHScript(signer.address())));

        RunarContract contract = new RunarContract(artifact, List.of(ScriptUtils.bytesToHex(signer.pubKey())));
        contract.deploy(provider, signer, 5_000L, signer.address());

        // claim(sig, txPreimage): both auto-resolved (null => SDK fills Sig +
        // SigHashPreimage). isStateful is false here, so neither param is
        // hidden from the caller — mirrors the TS N-085 repro's [null, null].
        contract.call("claim", Arrays.asList(null, null), null, provider, signer);

        List<String> txs = provider.getBroadcastedTxs();
        String callHex = txs.get(txs.size() - 1);
        RawTx parsed = RawTxParser.parse(callHex);

        long totalOut = 0L;
        for (RawTx.Output o : parsed.outputs) totalOut += o.satoshis;

        // Total input value: the contract's own deployed UTXO (5000 sats)
        // plus, if more than one input is present, the ONE funding UTXO this
        // test registered (100000 sats) — this test controls the entire UTXO
        // universe, so the input count alone determines which UTXOs were spent.
        long totalIn = 5_000L;
        if (parsed.inputs.size() > 1) totalIn += 100_000L;

        long actualFee = totalIn - totalOut;
        long feeRate = provider.getFeeRate();
        long txSizeBytes = callHex.length() / 2L;
        long requiredFee = new BigDecimal(txSizeBytes)
            .multiply(BigDecimal.valueOf(feeRate))
            .divide(BigDecimal.valueOf(1000), 0, RoundingMode.CEILING)
            .longValueExact();

        assertTrue(actualFee >= requiredFee,
            "fee too low: paid " + actualFee + " sats, required >= " + requiredFee
                + " sats (tx size " + txSizeBytes + " bytes, fee rate " + feeRate + " sat/KB)");
    }
}
