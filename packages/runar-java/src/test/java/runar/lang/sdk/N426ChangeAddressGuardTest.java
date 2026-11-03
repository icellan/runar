package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * N-426: the stateful change-address guard. Replays the shared cross-SDK vector
 * {@code conformance/sdk-call/n426-change-address-guard.json} (TS reference, Spend-validated in
 * conformance/sdk-call/n426-change-address-guard.test.ts).
 *
 * <p>Proves: on a stateful method that takes {@code _changePKH}, prepareCallWithOptions refuses
 * changeAddress for another key (no changePubKey) with the shared message and broadcasts
 * nothing; changeAddress + the matching changePubKey and changeAddress equal to the signer's own
 * address are accepted. Does not prove: the terminal path, finalizeCall, or a live node.
 */
class N426ChangeAddressGuardTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) {
        return (Map<String, Object>) o;
    }

    private static Map<String, Object> load(String name) throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call", name);
        return obj(Json.parse(Files.readString(p)));
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

    private record Fixture(RunarContract contract, MockProvider provider, LocalSigner signer) {}

    private static Fixture fresh(Map<String, Object> v) throws Exception {
        StringBuilder artifactJson = new StringBuilder();
        write(artifactJson, v.get("artifact"));
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson.toString());
        UTXO contractUtxo = utxo(v.get("contractUtxo"));
        LocalSigner signer = new LocalSigner((String) v.get("privKeyHex"));
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(), utxo(v.get("fundingUtxo")));
        provider.addKnownOutpoint(contractUtxo);
        return new Fixture(RunarContract.fromUtxo(artifact, contractUtxo), provider, signer);
    }

    private static PreparedCall prepare(Fixture f, CallOptions options) {
        List<Object> args = new ArrayList<>();
        args.add(null);
        return f.contract().prepareCallWithOptions("increment", args, options, f.provider(), f.signer());
    }

    @Test
    void refusesChangeAddressForAnotherKeyWithoutChangePubKey() throws Exception {
        Map<String, Object> g = load("n426-change-address-guard.json");
        Fixture f = fresh(load("stateful-merge-prepared.json"));
        String other = (String) g.get("otherAddress");
        String want = ((String) g.get("message")).replace("{changeAddress}", other);
        RuntimeException e = assertThrows(RuntimeException.class,
            () -> prepare(f, new CallOptions(null, null, null).withChangeAddress(other)));
        assertTrue(e.getMessage().contains(want), "message = " + e.getMessage());
        assertEquals(0, f.provider().getBroadcastedTxs().size());
    }

    @Test
    void acceptsChangeAddressWithMatchingChangePubKey() throws Exception {
        Map<String, Object> g = load("n426-change-address-guard.json");
        Fixture f = fresh(load("stateful-merge-prepared.json"));
        prepare(f, new CallOptions(null, null, null)
            .withChangeAddress((String) g.get("otherAddress"))
            .withChangePubKey((String) g.get("otherPubKeyHex")));
    }

    @Test
    void acceptsChangeAddressEqualToTheSignersOwnAddress() throws Exception {
        Map<String, Object> g = load("n426-change-address-guard.json");
        Fixture f = fresh(load("stateful-merge-prepared.json"));
        assertEquals(g.get("ownAddress"), f.signer().address());
        prepare(f, new CallOptions(null, null, null).withChangeAddress((String) g.get("ownAddress")));
    }
}
