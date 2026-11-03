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
            + "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdcc064dde0261ab76"
            + "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f"
            + "517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048af"
            + "e6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76"
            + "927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f"
            + "76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be"
            + "667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f032"
            + "2a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd00"
            + "9f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a88"
            + "0261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667e"
            + "f9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a"
            + "547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e82"
            + "7602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980"
            + "587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777473044022026341e69d87bdbd408f917d0d177"
            + "e23ba15cdbe264eee8ef3db43a0e24b8f8e902204a9ff2fa764f751219ef90506ec43cd029857187d0df5d53266d37c37610"
            + "666c4114751e76e8199196d454941c45d1b3a323f1433bd6034791010210274d840301000000ef9b6802354444eada24842d"
            + "68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db6"
            + "32adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fde5027676aa517f517f517f"
            + "517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f"
            + "517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffff"
            + "ffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f"
            + "76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7692"
            + "7f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e"
            + "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a0"
            + "6295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f"
            + "938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe00"
            + "9c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e886976"
            + "8254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295"
            + "ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163"
            + "041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280"
            + "517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e68"
            + "68687c7e6c7c7e7c7eaa7c820128947f7701207f7587776a00000000000000001027000000000000ffffffff65aac2c3937c"
            + "ec7e23b79ffef930425f26529a6eaa55625d2e2a92a74f092e560000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbb"
            + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006b483045022100f36ef3c338df1a91f1f115d9c2587d864651d8"
            + "078025704bf40b0bc95ac9c2e002207ea242ec1827505a84209754bb0e261594a51a76e69ddd63601734fe7013e203412102"
            + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff02581b000000000000fde70261ab"
            + "7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f51"
            + "7f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c"
            + "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048"
            + "afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f"
            + "76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7692"
            + "7f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c"
            + "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079"
            + "be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0"
            + "322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd"
            + "009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a"
            + "880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be66"
            + "7ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca26954"
            + "7a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e"
            + "827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e6759"
            + "80587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f7587776a0100000000000000479101000000000019"
            + "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000";

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

