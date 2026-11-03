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
 * N-253: since F-369/N-213 the OP_PUSH_TX signature is unused on the stateful
 * prepareCall path ({@code buildPushTxUnlock} ignores it; the on-chain script
 * derives it from the preimage), yet the path still computed and discarded one
 * per layout. The fix computes the preimage only.
 *
 * <p>Proves: a stateful merge prepareCallWithOptions (the shared N-286 vector:
 * primary + extra contract input) performs zero {@code computePushTxSig}
 * calls, counted through {@code OpPushTx.PUSH_TX_SIG_COUNT}; the control shows
 * the counter does see {@code computePushTxSig}. Byte-identity of the prepared
 * output is proven by N292StatefulMergePreparedTest. Says nothing about
 * {@code computePushTxSig} callers outside the SDK.
 */
class N253PrepareCallNoOpPushTxSignTest {

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
    void statefulPrepareCallComputesNoOpPushTxSignature() throws Exception {
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

        int before = OpPushTx.PUSH_TX_SIG_COUNT.get();
        PreparedCall prepared = contract.prepareCallWithOptions(
            (String) v.get("method"), args, options, provider, signer);
        assertEquals(expected.get("sighash"), ScriptUtils.bytesToHex(prepared.sighashes().get(0)));
        assertEquals(0, OpPushTx.PUSH_TX_SIG_COUNT.get() - before,
            "stateful prepareCall must not compute an OP_PUSH_TX signature");
    }

    @Test
    void controlComputePushTxSigIsCounted() {
        int before = OpPushTx.PUSH_TX_SIG_COUNT.get();
        RawTx tx = new RawTx();
        tx.addInput("aa".repeat(32), 0, "");
        OpPushTx.computePushTxSig(tx, 0, new byte[] {0x51}, 1000L, OpPushTx.SIGHASH_ALL_FORKID);
        assertEquals(before + 1, OpPushTx.PUSH_TX_SIG_COUNT.get());
    }
}
