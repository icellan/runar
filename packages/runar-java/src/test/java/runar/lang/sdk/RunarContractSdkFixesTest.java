package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Coverage for the ported call/terminal funding SDK fixes:
 *
 * <ul>
 *   <li>#131 — CallOptions.sequence + non-final default sequences when a
 *       non-zero locktime is set.</li>
 *   <li>#133 — coin-selected call() funding (not sweep) + maxFundingInputs cap.</li>
 *   <li>#134 — funding inputs signed by fundingSigner, not the method signer.</li>
 *   <li>#118 — CallOptions.feeUtxo: extra P2PKH fee input on the terminal tx.</li>
 * </ul>
 *
 * <p>The restore-path fixes (#119 / #132) live in
 * {@link RunarContractRestoreFixesTest}.
 */
class RunarContractSdkFixesTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    private static final String PRIV2 =
        "0000000000000000000000000000000000000000000000000000000000000abc";

    private static RunarArtifact loadArtifact(String rel) throws Exception {
        java.io.InputStream in = RunarContractSdkFixesTest.class.getClassLoader()
            .getResourceAsStream(rel);
        assertNotNull(in, "test artifact not found on classpath: " + rel);
        try (in) {
            return RunarArtifact.fromJson(new String(in.readAllBytes(),
                java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    private static RunarContract statefulCounter(MockProvider provider, LocalSigner signer,
                                                 long fundingSats, int fundingCount) throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/stateful-counter.runar.json");
        for (int i = 0; i < fundingCount; i++) {
            provider.addUtxo(signer.address(),
                new UTXO(String.format("%064x", 0xf0 + i), i, fundingSats,
                    ScriptUtils.buildP2PKHScript(signer.address())));
        }
        RunarContract contract = new RunarContract(artifact, List.of(BigInteger.ZERO));
        contract.setCurrentUtxo(new UTXO("cc".repeat(32), 0, 5_000L, contract.lockingScript()));
        // Phase A5 non-vacuity: the fail-closed MockProvider must also know the
        // outpoint this call spends — injecting it straight into the contract
        // bypasses the provider, which would then have nothing to check.
        provider.addKnownOutpoint(new UTXO("cc".repeat(32), 0, 5_000L, contract.lockingScript()));
        return contract;
    }

    // ------------------------------------------------------------------
    // #131 — sequence
    // ------------------------------------------------------------------

    @Test
    void nonZeroLocktimeMakesInputsNonFinal() throws Exception {
        MockProvider provider = new MockProvider();
        LocalSigner signer = new LocalSigner(PRIV);
        RunarContract contract = statefulCounter(provider, signer, 200_000L, 1);

        Map<String, Object> updates = Map.of("count", BigInteger.ONE);
        CallOptions opts = new CallOptions(updates, null, null, 500_000);
        RunarContract.CallOutcome out =
            contract.callWithOptions("increment", List.of(), opts, provider, signer);

        RawTx tx = RawTxParser.parse(out.rawTxHex());
        assertTrue(tx.inputs.size() >= 2, "contract + funding inputs");
        for (RawTx.Input in : tx.inputs) {
            assertEquals(0xfffffffeL, in.sequence,
                "a non-zero locktime must make every input non-final (0xfffffffe)");
        }
        assertEquals(500_000, tx.locktime);
    }

    @Test
    void zeroLocktimeKeepsInputsFinal() throws Exception {
        MockProvider provider = new MockProvider();
        LocalSigner signer = new LocalSigner(PRIV);
        RunarContract contract = statefulCounter(provider, signer, 200_000L, 1);

        RunarContract.CallOutcome out = contract.call(
            "increment", List.of(), Map.of("count", BigInteger.ONE), provider, signer);

        RawTx tx = RawTxParser.parse(out.rawTxHex());
        for (RawTx.Input in : tx.inputs) {
            assertEquals(0xffffffffL, in.sequence,
                "no/zero locktime keeps inputs final (0xffffffff)");
        }
    }

    @Test
    void explicitSequenceOverridesLocktimeDefault() throws Exception {
        MockProvider provider = new MockProvider();
        LocalSigner signer = new LocalSigner(PRIV);
        RunarContract contract = statefulCounter(provider, signer, 200_000L, 1);

        CallOptions opts = new CallOptions(Map.of("count", BigInteger.ONE), null, null, 500_000)
            .withSequence(0xfffffff0);
        RunarContract.CallOutcome out =
            contract.callWithOptions("increment", List.of(), opts, provider, signer);

        RawTx tx = RawTxParser.parse(out.rawTxHex());
        for (RawTx.Input in : tx.inputs) {
            assertEquals(0xfffffff0L, in.sequence, "explicit sequence wins over the locktime default");
        }
    }

    // ------------------------------------------------------------------
    // N-144 — CallOptions.satoshis (continuation-amount override)
    //
    // Before this fix, CallOptions had no `satoshis` field at all: the
    // generated typed wrapper's {Contract}StatefulCallOptions.satoshis was
    // read nowhere, so setting it silently did nothing — the continuation
    // always carried forward the spent UTXO's value. TS parity:
    // `options?.satoshis ?? singleExplicitStateSats ?? currentUtxo.satoshis`
    // (packages/runar-sdk/src/contract.ts).
    // ------------------------------------------------------------------

    @Test
    void explicitSatoshisOverridesContinuationAmount() throws Exception {
        MockProvider provider = new MockProvider();
        LocalSigner signer = new LocalSigner(PRIV);
        RunarContract contract = statefulCounter(provider, signer, 200_000L, 1);

        CallOptions opts = new CallOptions(Map.of("count", BigInteger.ONE), null, null)
            .withSatoshis(9_999L);
        RunarContract.CallOutcome out =
            contract.callWithOptions("increment", List.of(), opts, provider, signer);

        assertEquals(9_999L, out.nextContractUtxo().satoshis(),
            "CallOptions.satoshis must override the continuation amount — this used to be a "
                + "silent no-op because the field did not exist on CallOptions at all");
    }

    @Test
    void defaultOptionsKeepContinuationAtSpentUtxoSatoshis() throws Exception {
        MockProvider provider = new MockProvider();
        LocalSigner signer = new LocalSigner(PRIV);
        // statefulCounter() deploys the spendable UTXO at 5_000 sats.
        RunarContract contract = statefulCounter(provider, signer, 200_000L, 1);

        RunarContract.CallOutcome out = contract.call(
            "increment", List.of(), Map.of("count", BigInteger.ONE), provider, signer);

        assertEquals(5_000L, out.nextContractUtxo().satoshis(),
            "with no satoshis override, the continuation must keep the spent UTXO's value "
                + "(TS parity default) — unaffected by N-144, asserted as a companion guard");
    }

    // ------------------------------------------------------------------
    // #133 — coin-select funding + maxFundingInputs cap
    // ------------------------------------------------------------------

    @Test
    void fundingIsCoinSelectedNotSwept() throws Exception {
        MockProvider provider = new MockProvider();
        LocalSigner signer = new LocalSigner(PRIV);
        // Three large UTXOs — a single one covers the small fee, so the tx must
        // use ONE funding input, not sweep all three.
        RunarContract contract = statefulCounter(provider, signer, 200_000L, 3);

        RunarContract.CallOutcome out = contract.call(
            "increment", List.of(), Map.of("count", BigInteger.ONE), provider, signer);

        RawTx tx = RawTxParser.parse(out.rawTxHex());
        assertEquals(2, tx.inputs.size(),
            "coin selection must add only the one funding input the fee needs, not sweep the wallet");
    }

    @Test
    void maxFundingInputsCapFailsLoudly() throws Exception {
        MockProvider provider = new MockProvider();
        LocalSigner signer = new LocalSigner(PRIV);
        RunarContract contract = statefulCounter(provider, signer, 200_000L, 1);

        CallOptions opts = new CallOptions(Map.of("count", BigInteger.ONE), null, null)
            .withMaxFundingInputs(0);
        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> contract.callWithOptions("increment", List.of(), opts, provider, signer));
        assertTrue(e.getMessage().contains("maxFundingInputs"),
            "expected a maxFundingInputs cap error, got: " + e.getMessage());
    }

    // ------------------------------------------------------------------
    // #118 + #134 — terminal feeUtxo signed by fundingSigner
    // ------------------------------------------------------------------

    @Test
    void terminalFeeUtxoIsAddedAndSignedByFundingSigner() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        LocalSigner signer = new LocalSigner(PRIV);
        LocalSigner funding = new LocalSigner(PRIV2);
        MockProvider provider = new MockProvider();

        String pkhHex = java.util.HexFormat.of().formatHex(Hash160.hash160(signer.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));
        contract.setCurrentUtxo(new UTXO("ab".repeat(32), 0, 10_000L, contract.lockingScript()));
        // Phase A5 non-vacuity: the fail-closed MockProvider must also know the
        // outpoint this call spends — injecting it straight into the contract
        // bypasses the provider, which would then have nothing to check.
        provider.addKnownOutpoint(new UTXO("ab".repeat(32), 0, 10_000L, contract.lockingScript()));

        // Terminal output pays out the full contract balance → fee must come
        // from the feeUtxo (issue #118), owned/signed by the funding key (#134).
        List<CallOptions.TerminalOutput> outs = List.of(
            new CallOptions.TerminalOutput(BigInteger.valueOf(10_000L),
                signer.address(), null));
        UTXO feeUtxo = new UTXO("fe".repeat(32), 3, 5_000L,
            ScriptUtils.buildP2PKHScript(funding.address()));
        CallOptions opts = CallOptions.terminal(outs).withFeeUtxo(feeUtxo).withFundingSigner(funding);

        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null); args.add(null);
        RunarContract.CallOutcome out =
            contract.callWithOptions("unlock", args, opts, provider, signer);

        RawTx tx = RawTxParser.parse(out.rawTxHex());
        // Contract input + fee input at index 1.
        assertEquals(2, tx.inputs.size(), "terminal tx = contract input + fee input");
        assertEquals(feeUtxo.txid(), tx.inputs.get(1).prevTxid, "fee input sits at index 1");
        assertEquals(feeUtxo.outputIndex(), tx.inputs.get(1).prevVout);
        // No change output — only the terminal outputs; the feeUtxo is consumed
        // entirely as fee.
        assertEquals(1, tx.outputs.size(), "no change output on a terminal fee-utxo tx");
        // Fee = (contract + feeUtxo) - outputs = (10000 + 5000) - 10000 = 5000.
        long inSats = 10_000L + 5_000L;
        long outSats = tx.outputs.stream().mapToLong(o -> o.satoshis).sum();
        assertEquals(5_000L, inSats - outSats, "the feeUtxo is consumed entirely as fee");

        // The fee input's unlocking script pushes the FUNDING signer's pubkey
        // (issue #134), not the method signer's.
        String feeUnlock = tx.inputs.get(1).scriptSigHex;
        String fundingPubHex = ScriptUtils.bytesToHex(funding.pubKey());
        String methodPubHex = ScriptUtils.bytesToHex(signer.pubKey());
        assertTrue(feeUnlock.contains(fundingPubHex),
            "fee input must be signed with (and push) the funding signer's pubkey");
        assertFalse(feeUnlock.contains(methodPubHex),
            "fee input must NOT push the method signer's pubkey");
    }
}
