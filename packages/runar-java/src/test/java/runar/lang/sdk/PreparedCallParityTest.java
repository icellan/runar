package runar.lang.sdk;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-145: the multi-signer {@code prepareCall} / {@code finalizeCall} flow must
 * build exactly the transaction {@code call()} builds for the same inputs
 * (TS parity: {@code call()} IS {@code prepareCall} + sign + {@code finalizeCall}
 * in packages/runar-sdk/src/contract.ts).
 *
 * <p>Before the fix the non-terminal prepare path never ran the ANF
 * interpreter and laid the tx out with the legacy M8 builder: no OP_PUSH_TX
 * preimage, no funding, no change, the continuation always at the spent
 * UTXO's value — so a {@code CallOptions.satoshis} override and an explicit
 * {@code this.addOutput(<sats>, ...)} were both ignored.
 *
 * <p>Each case runs the same call twice on two identically set-up contracts
 * (each with its own MockProvider, so the mock txids line up): once through
 * {@code call}/{@code callWithOptions}, once through prepare + external
 * signing (the same deterministic RFC-6979 key over the published sighash) +
 * finalize, and asserts byte-identical tx hex, the same next UTXO and the same
 * post-state.
 *
 * <p>Proves: prepare+finalize and call agree byte for byte on the stateful
 * OP_PUSH_TX path (default, satoshis override, explicit addOutput amount,
 * interpreter-computed state, a user Sig slot signed externally), and the
 * MockProvider's fail-closed broadcast validation accepts both. Does NOT
 * prove: on-chain script validity (no Spend/node replay here — call()'s own
 * on-chain coverage carries that, and this test shows the prepare path now
 * emits call()'s bytes); multi-input (additionalContractInputs) or raw-output
 * interleaved prepare flows beyond sharing the same code path.
 */
class PreparedCallParityTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";

    private static RunarArtifact loadArtifact(String rel) throws Exception {
        java.io.InputStream in = PreparedCallParityTest.class.getClassLoader()
            .getResourceAsStream(rel);
        assertNotNull(in, "test artifact not found on classpath: " + rel);
        try (in) {
            return RunarArtifact.fromJson(new String(in.readAllBytes(),
                java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    /** One contract + provider + funded signer, ready to spend a 5000-sat UTXO. */
    private record Fixture(RunarContract contract, MockProvider provider, LocalSigner signer) {}

    private static Fixture fixture(String artifactRel, List<Object> ctorArgs,
                                   Function<LocalSigner, List<Object>> ctorFromSigner) throws Exception {
        RunarArtifact artifact = loadArtifact(artifactRel);
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(),
            new UTXO(String.format("%064x", 0xf0), 0, 200_000L,
                ScriptUtils.buildP2PKHScript(signer.address())));
        List<Object> args = ctorFromSigner != null ? ctorFromSigner.apply(signer) : ctorArgs;
        RunarContract contract = new RunarContract(artifact, args);
        UTXO spend = new UTXO("cc".repeat(32), 0, 5_000L, contract.lockingScript());
        contract.setCurrentUtxo(spend);
        provider.addKnownOutpoint(spend);
        return new Fixture(contract, provider, signer);
    }

    /** prepare → sign every published sighash with the fixture's key → finalize. */
    private static RunarContract.CallOutcome prepareSignFinalize(
        Fixture f, String method, List<Object> args, CallOptions options
    ) {
        PreparedCall prepared = f.contract().prepareCallWithOptions(
            method, args, options, f.provider(), f.signer());
        List<byte[]> sigs = new ArrayList<>();
        for (byte[] sighash : prepared.sighashes()) {
            sigs.add(f.signer().sign(sighash, null));
        }
        return f.contract().finalizeCall(prepared, sigs, f.provider());
    }

    private static void assertSameOutcome(
        Fixture viaCall, RunarContract.CallOutcome called,
        Fixture viaPrepare, RunarContract.CallOutcome prepared
    ) {
        assertEquals(called.rawTxHex(), prepared.rawTxHex(),
            "prepareCall + finalizeCall must emit the exact transaction call() emits");
        assertEquals(called.txid(), prepared.txid());
        assertEquals(called.nextContractUtxo(), prepared.nextContractUtxo(),
            "the tracked continuation UTXO must match call()'s");
        assertEquals(viaCall.contract().currentUtxo(), viaPrepare.contract().currentUtxo());
        assertEquals(viaCall.contract().state(), viaPrepare.contract().state(),
            "post-call state must match call()'s");
    }

    @Test
    void statefulDefaultOptionsMatchCall() throws Exception {
        Fixture a = fixture("artifacts/stateful-counter.runar.json", List.of(BigInteger.ZERO), null);
        Fixture b = fixture("artifacts/stateful-counter.runar.json", List.of(BigInteger.ZERO), null);

        RunarContract.CallOutcome called =
            a.contract().call("increment", List.of(), null, a.provider(), a.signer());
        PreparedCall p = b.contract().prepareCall("increment", List.of(), null, b.provider(), b.signer());
        assertTrue(p.sighashes().isEmpty(), "increment has no user Sig slot");
        RunarContract.CallOutcome prepared = b.contract().finalizeCall(p, List.of(), b.provider());

        assertSameOutcome(a, called, b, prepared);
        assertEquals(BigInteger.ONE, b.contract().state().get("count"),
            "the ANF interpreter must have run on the prepare path (0 -> 1)");
        assertEquals(5_000L, prepared.nextContractUtxo().satoshis());
    }

    @Test
    void statefulSatoshisOverrideMatchesCall() throws Exception {
        Fixture a = fixture("artifacts/stateful-counter.runar.json", List.of(BigInteger.ZERO), null);
        Fixture b = fixture("artifacts/stateful-counter.runar.json", List.of(BigInteger.ZERO), null);
        CallOptions opts = new CallOptions(null, null, null).withSatoshis(9_999L);

        RunarContract.CallOutcome called =
            a.contract().callWithOptions("increment", List.of(), opts, a.provider(), a.signer());
        RunarContract.CallOutcome prepared = prepareSignFinalize(b, "increment", List.of(), opts);

        assertSameOutcome(a, called, b, prepared);
        assertEquals(9_999L, prepared.nextContractUtxo().satoshis(),
            "CallOptions.satoshis must set the continuation amount on the prepare path too");
        assertEquals(9_999L, RawTxParser.parse(prepared.rawTxHex()).outputs.get(0).satoshis);
    }

    @Test
    void explicitStateUpdatesMatchCall() throws Exception {
        Fixture a = fixture("artifacts/stateful-counter.runar.json", List.of(BigInteger.ZERO), null);
        Fixture b = fixture("artifacts/stateful-counter.runar.json", List.of(BigInteger.ZERO), null);
        Map<String, Object> st = Map.of("count", BigInteger.ONE);

        RunarContract.CallOutcome called =
            a.contract().call("increment", List.of(), st, a.provider(), a.signer());
        PreparedCall p = b.contract().prepareCall("increment", List.of(), st, b.provider(), b.signer());
        RunarContract.CallOutcome prepared = b.contract().finalizeCall(p, List.of(), b.provider());

        assertSameOutcome(a, called, b, prepared);
    }

    @Test
    void explicitAddOutputSatoshisMatchCall() throws Exception {
        // SatCounter.inc(): this.count++; this.addOutput(1000n, this.count).
        Fixture a = fixture("artifacts/sat-counter.runar.json", List.of(BigInteger.valueOf(5)), null);
        Fixture b = fixture("artifacts/sat-counter.runar.json", List.of(BigInteger.valueOf(5)), null);

        RunarContract.CallOutcome called =
            a.contract().call("inc", List.of(), null, a.provider(), a.signer());
        RunarContract.CallOutcome prepared = prepareSignFinalize(b, "inc", List.of(), null);

        assertSameOutcome(a, called, b, prepared);
        assertEquals(1_000L, RawTxParser.parse(prepared.rawTxHex()).outputs.get(0).satoshis,
            "explicit addOutput(1000) must set the continuation amount on the prepare path");
        assertEquals(BigInteger.valueOf(6), b.contract().state().get("count"));
    }

    @Test
    void statefulUserSigSignedExternallyMatchesCall() throws Exception {
        // FungibleToken.send(sig, to, outputSatoshis): a stateful method with a
        // user Sig slot — the multi-signer case prepare/finalize exists for.
        Function<LocalSigner, List<Object>> ctor = s -> List.of(
            ScriptUtils.bytesToHex(s.pubKey()), BigInteger.valueOf(100), BigInteger.ZERO, "abcd");
        Fixture a = fixture("artifacts/token-ft.runar.json", null, ctor);
        Fixture b = fixture("artifacts/token-ft.runar.json", null, ctor);
        String to = ScriptUtils.bytesToHex(a.signer().pubKey());
        List<Object> args = java.util.Arrays.asList(null, to, BigInteger.valueOf(1_000));

        RunarContract.CallOutcome called = a.contract().call("send", args, null, a.provider(), a.signer());
        PreparedCall p = b.contract().prepareCallWithOptions("send", args, null, b.provider(), b.signer());
        assertEquals(List.of(0), p.sigIndices());
        RunarContract.CallOutcome prepared = b.contract().finalizeCall(
            p, List.of(b.signer().sign(p.sighashes().get(0), null)), b.provider());

        assertSameOutcome(a, called, b, prepared);
    }
}
