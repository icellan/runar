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
 * (ref-outputs.ts).
 *
 * <p>Proves: given the same inputs, the Java SDK's callWithOptions with one
 * 7000-sat output spec emits a tx byte-equal to the TS reference, and tracks
 * that output as the next contract UTXO. Does not prove script validity of
 * that tx (the covenant rejects it by design), more than one output spec,
 * the prepare/finalize path, or a live node.
 */
class N430StatefulOutputsTest {

    private static final String TS_REFERENCE_TX_HEX = ""
            + "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc0064dd80261ab76"
            + "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f"
            + "517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeff"
            + "ffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82"
            + "927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f"
            + "82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac"
            + "55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4"
            + "939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602"
            + "fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e88"
            + "69768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a0"
            + "6295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c"
            + "9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f63"
            + "5280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c"
            + "7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777473044022017278639d4dd320488b06407f21aa7b396a9bf6c"
            + "49e926d09a235099eff216230220757f33f91c349818f3e98c3152366b19f8cfcc31796a26c4b54639a8653deee64114751e"
            + "76e8199196d454941c45d1b3a323f1433bd6034891010210274d7e0301000000ef9b6802354444eada24842d68525e3b2860"
            + "d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaa"
            + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddf027676aa517f517f517f517f517f517f"
            + "517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff"
            + "007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f"
            + "82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f8292"
            + "7f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce"
            + "28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a"
            + "5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c"
            + "6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d"
            + "7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d9"
            + "59f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c"
            + "58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f6353"
            + "80527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c82"
            + "0128947f7701207f7587776a00000000000000001027000000000000ffffffffe0fd11d1d8cc68dfb5eb1befacea0bf64abd"
            + "7abb4e7718d31db20f5f47bcf4850000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            + "bbbbbbbbbbbbbbbb000000006a473044022051b0c95a50f818200f25a260babfbc6ab7fb3a08b0b06d804047ac65631d6547"
            + "022016be559e9692ff3ab4a470a4ec2b591e5680021b50798253c6120087a6315eae41210279be667ef9dcbbac55a06295ce"
            + "870b07029bfcdb2dce28d959f2815b16f81798ffffffff02581b000000000000fde10261ab7676aa517f517f517f517f517f"
            + "517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f"
            + "517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffff"
            + "ffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82"
            + "927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f"
            + "82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb"
            + "2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432"
            + "dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff"
            + "009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101"
            + "419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce"
            + "28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac"
            + "7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f"
            + "635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa"
            + "7c820128947f7701207f7587776a010000000000000048910100000000001976a914751e76e8199196d454941c45d1b3a323"
            + "f1433bd688ac00000000";

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

