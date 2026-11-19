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
 * N-430: a stateful call with caller-specified continuation outputs
 * ({@code CallOptions.outputs}, TS parity: {@code options.outputs}).
 *
 * <p>The reference tx below was built by the TS SDK
 * ({@code RunarContract.call('increment', [null], {outputs: [{satoshis: 7000,
 * state: {count: 1n}}]})}) on the inputs of
 * {@code conformance/sdk-call/stateful-merge-prepared.json} (MergeCounter
 * artifact, contract UTXO 10000 sat, funding UTXO, key 1, MockProvider default
 * fee rate), with script validation off because the covenant itself rejects a
 * 7000-sat continuation. Derivation script: see the N-430 remediation log
 * (ref-outputs.ts). Re-derived with the same TS call after D25 changed
 * MergeCounter.increment to an explicit addOutput (the vector's artifact moved).
 *
 * <p>Proves: given the same inputs, the Java SDK's callWithOptions with one
 * 7000-sat output spec emits a tx byte-equal to the TS reference, and tracks
 * that output as the next contract UTXO. Does not prove script validity of
 * that tx (the covenant rejects it by design), more than one output spec,
 * the prepare/finalize path, or a live node.
 */
class N430StatefulOutputsTest {

    private static final String TS_REFERENCE_TX_HEX = ""
            + "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdb0064dd10261ab52"
            + "798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f51"
            + "7f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c"
            + "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048"
            + "afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f"
            + "82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f8292"
            + "7f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c"
            + "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079"
            + "be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8c"
            + "f12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd"
            + "009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f82599d517f75016a"
            + "880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781547a210279be66"
            + "7ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad78820134947f77587f7581788b5679016a7e7c58"
            + "807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e"
            + "675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b75"
            + "77687eaa7b820128947f7701207f75877777483045022100c19fc63ebda22a5b95203da345bc49fe8c6898048efaaa37e099"
            + "38b7276a6b78022077b88519034f76bbde4a25af83c036988409ad45d40a76302a5a20aa6933a7344114751e76e8199196d4"
            + "54941c45d1b3a323f1433bd6034b91014d770301000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438"
            + "eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaa"
            + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd80252798201149d757676aa517f517f517f517f517f517f517f"
            + "517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d"
            + "97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f8292"
            + "7f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82"
            + "927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d9"
            + "59f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c19"
            + "05608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375"
            + "587f776775527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601"
            + "687f7782012c947f758258947f758258947f7781547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2"
            + "815b16f81798ad78820134947f77587f7581788b5679016a7e7c58807e827602fd009f635280517f756776030000019f6353"
            + "80527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a54"
            + "7a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f758777776a00000000"
            + "000000001027000000000000fffffffff3198a0edb9df01eb7958c40bd258389ba920498ec6a1a6a9689e6750c1363ef0000"
            + "000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a473044"
            + "02204aa0823c38c2be6cfc827a87c41e080c5c724f5e7eeacb145b54293ed548d94e022000a21757b345caa3fe483c1bf61a"
            + "8f1285b16bc968c30f118b40e2c0a7b585e941210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16"
            + "f81798ffffffff02581b000000000000fdda0261ab52798201149d757676aa517f517f517f517f517f517f517f517f517f51"
            + "7f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c"
            + "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c"
            + "7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d9778529678"
            + "9f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82"
            + "927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f"
            + "82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c"
            + "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16"
            + "f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218"
            + "ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775"
            + "527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f778201"
            + "2c947f758258947f758258947f7781547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"
            + "98ad78820134947f77587f7581788b5679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501"
            + "fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c"
            + "9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f758777776a01000000000000004b"
            + "910100000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000";

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
    void statefulCallWithOutputsReproducesTheTsReferenceTx() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call",
            "stateful-merge-prepared.json");
        Map<String, Object> v = obj(Json.parse(Files.readString(p)));

        StringBuilder artifactJson = new StringBuilder();
        write(artifactJson, v.get("artifact"));
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson.toString());

        UTXO contractUtxo = utxo(v.get("contractUtxo"));
        UTXO fundingUtxo = utxo(v.get("fundingUtxo"));
        LocalSigner signer = new LocalSigner((String) v.get("privKeyHex"));
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(), fundingUtxo);
        provider.addKnownOutpoint(contractUtxo);
        RunarContract contract = RunarContract.fromUtxo(artifact, contractUtxo);

        List<Object> args = new ArrayList<>();
        args.add(null);
        CallOptions options = new CallOptions(null, null, null).withOutputs(List.of(
            new CallOptions.OutputSpec(BigInteger.valueOf(7000), Map.of("count", BigInteger.ONE))));
        RunarContract.CallOutcome out = contract.callWithOptions(
            (String) v.get("method"), args, options, provider, signer);

        assertEquals(TS_REFERENCE_TX_HEX, out.rawTxHex(),
            "callWithOptions(outputs) must emit the TS reference tx");
        assertEquals(7000L, out.nextContractUtxo().satoshis());
        assertEquals(0, out.nextContractUtxo().outputIndex());
    }
}

