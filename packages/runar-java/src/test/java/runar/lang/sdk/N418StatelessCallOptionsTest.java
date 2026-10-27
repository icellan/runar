package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * N-418: the stateless (non-OP_PUSH_TX) call path must take the same
 * {@link CallOptions} the TS SDK honours there (packages/runar-sdk/src/contract.ts,
 * the shared non-terminal build: {@code changeAddress}, {@code locktime} /
 * {@code sequence}, {@code maxFundingInputs}, {@code fundingSigner}).
 *
 * <p>Uses the {@code peek} method of the shared vector
 * {@code conformance/sdk-call/stateless-witness.json} (a stateless method with no
 * Sig, so input 0's unlock is the same under every option). Base case: the vector's
 * own TS {@code referenceTxHex}; each option test compares against what TS builds
 * for the same inputs, derived from TS semantics:
 * <ul>
 *   <li>changeAddress: the change output pays P2PKH({@code changeAddress}) instead
 *       of the signer (TS: {@code buildP2PKHScript(options?.changeAddress ?? address)});
 *       funding is still looked up at the signer's address.</li>
 *   <li>locktime: tx nLockTime = locktime and every input's nSequence is 0xfffffffe
 *       (TS {@code resolveInputSequence}); an explicit {@code sequence} wins.</li>
 *   <li>maxFundingInputs: more funding inputs than the cap is a refusal, not a
 *       silent sweep.</li>
 *   <li>fundingSigner: the P2PKH funding input is signed by it (its pubkey is
 *       pushed); the method signer still funds the lookup and gets the change.</li>
 * </ul>
 *
 * <p>Proves: each option reaches the stateless tx, in call() and in
 * prepareCallWithOptions + finalizeCall, and the no-option call is unchanged
 * (whole-tx equal to the TS reference). Does not prove: live-node acceptance, the
 * stateful / OP_PUSH_TX path (which ignores changeAddress by design), or
 * multi-UTXO selection order.
 */
class N418StatelessCallOptionsTest {

    private static final String OTHER_PRIV =
        "0000000000000000000000000000000000000000000000000000000000000abc";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) {
        return (Map<String, Object>) o;
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                write(sb, e.getKey().toString());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List<?> l) {
            sb.append('[');
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) sb.append(',');
                write(sb, l.get(i));
            }
            sb.append(']');
        } else if (v instanceof String s) {
            sb.append('"');
            for (char c : s.toCharArray()) {
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    default -> {
                        if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                        else sb.append(c);
                    }
                }
            }
            sb.append('"');
        } else {
            sb.append(v);
        }
    }

    private static UTXO utxo(Object o) {
        Map<String, Object> u = obj(o);
        return new UTXO((String) u.get("txid"), ((Number) u.get("outputIndex")).intValue(),
            ((Number) u.get("satoshis")).longValue(), (String) u.get("script"));
    }

    private record Fixture(Map<String, Object> v, RunarContract contract, MockProvider provider,
                           LocalSigner signer, UTXO funding) {}

    /** {@code fundingScript} null → the vector's own funding UTXO. */
    private static Fixture fresh(String fundingScript) throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call",
            "stateless-witness.json");
        Map<String, Object> v = obj(Json.parse(Files.readString(p)));
        StringBuilder artifactJson = new StringBuilder();
        write(artifactJson, v.get("artifact"));
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson.toString());
        UTXO contractUtxo = utxo(v.get("contractUtxo"));
        LocalSigner signer = new LocalSigner((String) v.get("privKeyHex"));
        UTXO vectorFunding = utxo(v.get("fundingUtxo"));
        UTXO funding = fundingScript == null ? vectorFunding
            : new UTXO(vectorFunding.txid(), vectorFunding.outputIndex(), vectorFunding.satoshis(),
                fundingScript);
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(), funding);
        provider.addKnownOutpoint(contractUtxo);
        RunarContract contract = RunarContract.fromUtxo(artifact, contractUtxo);
        contract.setPrevOutScript(0, (String) v.get("prevOutScriptHex"));
        return new Fixture(v, contract, provider, signer, funding);
    }

    private static List<Object> peekArgs() {
        return List.of(BigInteger.valueOf(5));
    }

    private static String referencePeek(Fixture f) {
        return (String) obj(obj(f.v().get("expected")).get("peek")).get("referenceTxHex");
    }

    @Test
    void noOptionsCallStillEqualsTheTsReference() throws Exception {
        Fixture f = fresh(null);
        RunarContract.CallOutcome out = f.contract().callWithOptions("peek", peekArgs(),
            new CallOptions(null, null, null), f.provider(), f.signer());
        assertEquals(referencePeek(f), out.rawTxHex());
    }

    @Test
    void changeAddressPaysTheChangeOutputToThatAddress() throws Exception {
        Fixture f = fresh(null);
        LocalSigner other = new LocalSigner(OTHER_PRIV);
        RunarContract.CallOutcome out = f.contract().callWithOptions("peek", peekArgs(),
            new CallOptions(null, null, null).withChangeAddress(other.address()),
            f.provider(), f.signer());
        RawTx tx = RawTxParser.parse(out.rawTxHex());
        assertEquals(1, tx.outputs.size(), "stateless call: change output only");
        assertEquals(ScriptUtils.buildP2PKHScript(other.address()), tx.outputs.get(0).scriptPubKeyHex,
            "change must go to options.changeAddress, not the signer");
        // Same inputs, same fee: only the change script differs from the TS reference.
        assertEquals(RawTxParser.parse(referencePeek(f)).outputs.get(0).satoshis,
            tx.outputs.get(0).satoshis);
    }

    @Test
    void locktimeSetsNLockTimeAndNonFinalSequenceOnEveryInput() throws Exception {
        Fixture f = fresh(null);
        RunarContract.CallOutcome out = f.contract().callWithOptions("peek", peekArgs(),
            new CallOptions(null, null, null).withLocktime(500_000), f.provider(), f.signer());
        RawTx tx = RawTxParser.parse(out.rawTxHex());
        assertEquals(500_000, tx.locktime);
        assertEquals(2, tx.inputs.size());
        for (RawTx.Input in : tx.inputs) {
            assertEquals(0xfffffffeL, in.sequence,
                "a non-zero locktime defaults every input to 0xfffffffe (TS resolveInputSequence)");
        }
    }

    @Test
    void explicitSequenceWinsOverTheLocktimeDefault() throws Exception {
        Fixture f = fresh(null);
        RunarContract.CallOutcome out = f.contract().callWithOptions("peek", peekArgs(),
            new CallOptions(null, null, null).withLocktime(500_000).withSequence(7),
            f.provider(), f.signer());
        RawTx tx = RawTxParser.parse(out.rawTxHex());
        assertEquals(500_000, tx.locktime);
        for (RawTx.Input in : tx.inputs) assertEquals(7L, in.sequence);
    }

    @Test
    void maxFundingInputsBelowWhatTheFeeNeedsIsRefused() throws Exception {
        Fixture f = fresh(null);
        IllegalStateException e = assertThrows(IllegalStateException.class, () ->
            f.contract().callWithOptions("peek", peekArgs(),
                new CallOptions(null, null, null).withMaxFundingInputs(0), f.provider(), f.signer()));
        assertTrue(e.getMessage().contains("maxFundingInputs=0"), e.getMessage());
        // A cap that is sufficient changes nothing.
        Fixture g = fresh(null);
        RunarContract.CallOutcome out = g.contract().callWithOptions("peek", peekArgs(),
            new CallOptions(null, null, null).withMaxFundingInputs(1), g.provider(), g.signer());
        assertEquals(referencePeek(g), out.rawTxHex());
    }

    @Test
    void fundingSignerSignsTheFundingInput() throws Exception {
        LocalSigner other = new LocalSigner(OTHER_PRIV);
        Fixture f = fresh(ScriptUtils.buildP2PKHScript(other.address()));
        RunarContract.CallOutcome out = f.contract().callWithOptions("peek", peekArgs(),
            new CallOptions(null, null, null).withFundingSigner(other), f.provider(), f.signer());
        RawTx tx = RawTxParser.parse(out.rawTxHex());
        String fundScriptSig = tx.inputs.get(1).scriptSigHex;
        assertTrue(fundScriptSig.endsWith(ScriptUtils.encodePushData(ScriptUtils.bytesToHex(other.pubKey()))),
            "funding input must push the fundingSigner's pubkey");
        assertFalse(fundScriptSig.contains(ScriptUtils.bytesToHex(f.signer().pubKey())),
            "funding input must not carry the method signer's pubkey");
    }

    @Test
    void prepareCallWithOptionsHonoursTheSameOptions() throws Exception {
        Fixture f = fresh(null);
        LocalSigner other = new LocalSigner(OTHER_PRIV);
        PreparedCall prepared = f.contract().prepareCallWithOptions("peek", peekArgs(),
            new CallOptions(null, null, null).withChangeAddress(other.address()).withLocktime(500_000),
            f.provider(), f.signer());
        RawTx tx = RawTxParser.parse(prepared.txHex());
        assertEquals(ScriptUtils.buildP2PKHScript(other.address()), tx.outputs.get(0).scriptPubKeyHex);
        assertEquals(500_000, tx.locktime);
        for (RawTx.Input in : tx.inputs) assertEquals(0xfffffffeL, in.sequence);

        Fixture g = fresh(null);
        assertThrows(IllegalStateException.class, () ->
            g.contract().prepareCallWithOptions("peek", peekArgs(),
                new CallOptions(null, null, null).withMaxFundingInputs(0), g.provider(), g.signer()));
    }
}
