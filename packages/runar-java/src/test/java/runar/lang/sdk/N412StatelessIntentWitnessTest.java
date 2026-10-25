package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * N-412: a STATELESS contract method that takes the auto-injected intent
 * witness {@code _prevOutScript_0}. Replays the shared cross-SDK vector
 * {@code conformance/sdk-call/stateless-witness.json} (produced by the TS SDK,
 * whose MockProvider Spend-validated every input; re-checked with @bsv/sdk
 * Spend, including a tampered/omitted witness push, in
 * {@code conformance/sdk-call/stateless-witness.test.ts}).
 *
 * <p>Proves: the Java SDK's call (no-Sig {@code peek}, Sig {@code spend}) and
 * prepareCall + finalizeCall ({@code spend}) push
 * {@code <declared args> <witness> <selector>} on input 0, byte-equal to the
 * TS reference (for {@code call(spend)}, everything after the signature push).
 * Before N-412 Java pushed the witness AFTER the selector.
 *
 * <p>N-417: also proves WHOLE-tx equality with the TS reference for all three
 * paths (peek, spend, prepare+finalize): the P2PKH funding input, the change
 * output and the fee paid from the funding input, not out of the contract input.
 *
 * <p>Does not prove: a live node, a stateful call's funding (covered elsewhere),
 * the {@code fundingSigner}/{@code changeAddress} options on a stateless call,
 * nor {@code _serialisedOutputs} on a stateless method (the compiler refuses
 * requireOutputP2PKH outside StatefulSmartContract).
 */
class N412StatelessIntentWitnessTest {

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
                           LocalSigner signer) {}

    private static Fixture fresh() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call",
            "stateless-witness.json");
        Map<String, Object> v = obj(Json.parse(Files.readString(p)));
        StringBuilder artifactJson = new StringBuilder();
        write(artifactJson, v.get("artifact"));
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson.toString());
        UTXO contractUtxo = utxo(v.get("contractUtxo"));
        LocalSigner signer = new LocalSigner((String) v.get("privKeyHex"));
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(), utxo(v.get("fundingUtxo")));
        provider.addKnownOutpoint(contractUtxo);
        RunarContract contract = RunarContract.fromUtxo(artifact, contractUtxo);
        contract.setPrevOutScript(0, (String) v.get("prevOutScriptHex"));
        return new Fixture(v, contract, provider, signer);
    }

    private static String input0(String rawTxHex) {
        return RawTxParser.parse(rawTxHex).inputs.get(0).scriptSigHex;
    }

    /** Drops the leading signature push (one length byte + that many bytes). */
    private static String afterFirstPush(String scriptHex) {
        int len = Integer.parseInt(scriptHex.substring(0, 2), 16);
        return scriptHex.substring(2 + 2 * len);
    }

    @Test
    void callPeekPushesTheWitnessBeforeTheSelector() throws Exception {
        Fixture f = fresh();
        RunarContract.CallOutcome out = f.contract().call("peek", List.of(BigInteger.valueOf(5)), null,
            f.provider(), f.signer());
        assertEquals(obj(obj(f.v().get("expected")).get("peek")).get("input0UnlockingHex"), input0(out.rawTxHex()),
            "input-0 unlocking script must be <x> <witness> <selector>");
        assertEquals(obj(obj(f.v().get("expected")).get("peek")).get("referenceTxHex"), out.rawTxHex(),
            "N-417: the whole broadcast tx (P2PKH funding input, change output, fee) must equal the TS reference");
    }

    @Test
    void callSpendPushesTheWitnessBeforeTheSelector() throws Exception {
        Fixture f = fresh();
        List<Object> args = new ArrayList<>();
        args.add(null);
        args.add(f.v().get("pubKeyHex"));
        RunarContract.CallOutcome out = f.contract().call("spend", args, null, f.provider(), f.signer());
        String want = (String) obj(obj(f.v().get("expected")).get("spend")).get("input0UnlockingHex");
        assertEquals(afterFirstPush(want), afterFirstPush(input0(out.rawTxHex())),
            "after the Sig push, input 0 must be <pubKey> <witness> <selector>");
        assertEquals(obj(obj(f.v().get("expected")).get("spend")).get("referenceTxHex"), out.rawTxHex(),
            "N-417: the whole broadcast tx (incl. the contract-input signature) must equal the TS reference");
    }

    @Test
    void prepareFinalizeSpendPushesTheWitnessBeforeTheSelector() throws Exception {
        Fixture f = fresh();
        Map<String, Object> spend = obj(obj(f.v().get("expected")).get("spend"));
        List<Object> args = new ArrayList<>();
        args.add(null);
        args.add(f.v().get("pubKeyHex"));
        PreparedCall prepared = f.contract().prepareCall("spend", args, f.provider(), f.signer());
        assertEquals(List.of(0), prepared.sigIndices());
        String sigHex = (String) spend.get("signatureHex");
        // Java's finalizeCall appends the sighash flag byte itself: pass bare DER.
        byte[] der = ScriptUtils.hexToBytes(sigHex.substring(0, sigHex.length() - 2));
        RunarContract.CallOutcome out = f.contract().finalizeCall(prepared, List.of(der), f.provider());
        assertEquals(spend.get("input0UnlockingHex"), input0(out.rawTxHex()),
            "input-0 unlocking script must be <sig> <pubKey> <witness> <selector>");
        assertEquals(spend.get("referenceTxHex"), out.rawTxHex(),
            "N-417: prepareCall + finalizeCall must produce the same whole tx as the TS reference");
    }
}
