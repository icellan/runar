package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * N-286: a stateful merge through the two-phase API (prepareCall /
 * finalizeCall). Replays the shared cross-SDK vector
 * {@code conformance/sdk-call/stateful-merge-prepared.json} (produced by the TS
 * SDK, whose MockProvider Spend-validated all three inputs; re-checked with
 * Spend in {@code conformance/sdk-call/stateful-merge.test.ts}).
 *
 * <p>N-292: Java's two-phase merge used to broadcast the extra contract input
 * with an all-zero Sig (its auto-sign slot was lost because the primary args
 * it copies were already placeholdered) and to pay the fee out of the second
 * contract input's value instead of adding a P2PKH funding input as TS does.
 *
 * <p>Proves: given the vector's artifact, two contract UTXOs, funding UTXO and
 * key, the Java SDK's prepareCallWithOptions yields the same primary sighash
 * and sig indices, and finalizeCall with the vector's primary signature emits
 * a tx byte-equal to the TS reference (extra contract input's signed unlock,
 * the funding input, fee and change included). Because the reference tx was
 * Spend-validated on all three inputs by the TS generator, byte equality
 * carries that acceptance over. Does not prove a live node, per-input args
 * overrides, allPrevouts, or multi-UTXO funding selection.
 */
class N292StatefulMergePreparedTest {

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

    @Test
    void statefulMergeThroughPrepareFinalizeReproducesTheSharedTsVector() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call",
            "stateful-merge-prepared.json");
        Map<String, Object> v = obj(Json.parse(Files.readString(p)));
        Map<String, Object> expected = obj(v.get("expected"));

        StringBuilder artifactJson = new StringBuilder();
        write(artifactJson, v.get("artifact"));
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson.toString());

        UTXO contractUtxo = utxo(v.get("contractUtxo"));
        UTXO extraUtxo = utxo(v.get("extraContractUtxo"));
        UTXO fundingUtxo = utxo(v.get("fundingUtxo"));

        LocalSigner signer = new LocalSigner((String) v.get("privKeyHex"));
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(), fundingUtxo);
        provider.addKnownOutpoint(contractUtxo);
        provider.addKnownOutpoint(extraUtxo);
        RunarContract contract = RunarContract.fromUtxo(artifact, contractUtxo);

        List<Object> args = new ArrayList<>();
        args.add(null);
        CallOptions options = new CallOptions(null, null, null, null, null, null, null, null,
            List.of(extraUtxo), null);
        PreparedCall prepared = contract.prepareCallWithOptions(
            (String) v.get("method"), args, options, provider, signer);

        assertEquals(List.of(0), prepared.sigIndices());
        assertEquals(expected.get("sighash"), ScriptUtils.bytesToHex(prepared.sighashes().get(0)));

        String sigHex = (String) expected.get("primarySignatureHex");
        // Java's finalizeCall appends the sighash flag byte itself: pass bare DER.
        byte[] der = ScriptUtils.hexToBytes(sigHex.substring(0, sigHex.length() - 2));
        RunarContract.CallOutcome out = contract.finalizeCall(prepared, List.of(der), provider);
        assertEquals(expected.get("referenceTxHex"), out.rawTxHex(),
            "prepareCall + finalizeCall must emit the TS reference merge tx");
    }
}
