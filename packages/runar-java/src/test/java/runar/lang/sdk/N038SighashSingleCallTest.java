package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * N-038 (R64) — the cross-SDK SIGHASH_SINGLE stateful call vector
 * ({@code conformance/sdk-call/sighash-single-stateful.json}, TS reference,
 * replayed through {@code @bsv/sdk} Spend by
 * {@code conformance/sdk-call/sdk-call.test.ts}).
 *
 * <p>BIP-143 SINGLE commits hashOutputs to hash256(output[0]) only and zeroes
 * hashSequence, so the contract input's unlocking script depends only on the
 * inputs and the continuation output, not on change or fee policy. The SINGLE
 * method's ABI declares no {@code _changePKH} / {@code _changeAmount}, so none is
 * pushed; the change output is still built (protected by the funding input's
 * own signature, not by the covenant).
 *
 * <p>Proves: the Java SDK builds the {@code bump} call from the vector's
 * contract and funding UTXOs with a byte-identical input-0 unlocking script,
 * the same output 0, a change output, and the auto-computed new state. Does NOT
 * prove on-chain acceptance by itself (this tier ships no Script VM); the bytes
 * it matches are the ones Spend accepts in the TS test. ContractSimulator is not
 * used here: it hosts a Java contract class, and {@code @sighash} has no Java
 * surface spelling.
 */
class N038SighashSingleCallTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) {
        return (Map<String, Object>) o;
    }

    /** Minimal JSON writer for the parsed artifact subtree (Map/List/String/Number/Boolean/null). */
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

    @Test
    void singleStatefulCallWithChangeReproducesTheSharedTsVector() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call",
            "sighash-single-stateful.json");
        Map<String, Object> v = obj(Json.parse(Files.readString(p)));
        Map<String, Object> expected = obj(v.get("expected"));

        StringBuilder artifactJson = new StringBuilder();
        write(artifactJson, v.get("artifact"));
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson.toString());

        RunarArtifact.ABIMethod bump = artifact.abi().methods().stream()
            .filter(m -> m.name().equals("bump")).findFirst().orElseThrow();
        assertEquals(List.of("txPreimage"), bump.params().stream().map(RunarArtifact.ABIParam::name).toList(),
            "the SINGLE method takes no change params");
        assertTrue(bump.hasContinuation(), "the SINGLE method still continues the contract");

        Map<String, Object> cu = obj(v.get("contractUtxo"));
        Map<String, Object> fu = obj(v.get("fundingUtxo"));
        UTXO contractUtxo = new UTXO((String) cu.get("txid"), ((Number) cu.get("outputIndex")).intValue(),
            ((Number) cu.get("satoshis")).longValue(), (String) cu.get("script"));
        UTXO fundingUtxo = new UTXO((String) fu.get("txid"), ((Number) fu.get("outputIndex")).intValue(),
            ((Number) fu.get("satoshis")).longValue(), (String) fu.get("script"));

        LocalSigner signer = new LocalSigner((String) v.get("privKeyHex"));
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(), fundingUtxo);
        provider.addKnownOutpoint(contractUtxo);
        RunarContract contract = RunarContract.fromUtxo(artifact, contractUtxo);

        RunarContract.CallOutcome out = contract.call("bump", List.of(), null, provider, signer);
        RawTx tx = RawTxParser.parse(out.rawTxHex());

        assertEquals(expected.get("input0UnlockingHex"), tx.inputs.get(0).scriptSigHex,
            "input-0 unlocking script must equal the TS vector (no _changePKH/_changeAmount push)");
        Map<String, Object> out0 = obj(expected.get("output0"));
        assertEquals(((Number) out0.get("satoshis")).longValue(), tx.outputs.get(0).satoshis);
        assertEquals(out0.get("scriptHex"), tx.outputs.get(0).scriptPubKeyHex);
        assertEquals(((Number) expected.get("outputCount")).intValue(), tx.outputs.size(),
            "continuation + change");
        assertEquals(BigInteger.ONE, contract.state().get("count"));
    }
}
