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
 * N-296: cross-tier rule for an explicit Sig in a merge's per-input args
 * ({@code additionalContractInputArgs}): a Sig slot the primary call left
 * auto-signed (null) is ALWAYS signed by the connected signer for each
 * additional contract input; a caller-supplied value in that slot is
 * overwritten (TS reference).
 *
 * <p>Proves: on the inputs of {@code conformance/sdk-call/stateful-merge-prepared.json},
 * {@code call} with (a) no per-input args and (b) an explicit garbage Sig in
 * the per-input args broadcasts a tx byte-equal to {@link #REFERENCE_TX_HEX}
 * (derived by the TS SDK, Spend-validated on all three inputs by its
 * MockProvider). Does not prove: the other tiers (own tests, same constant),
 * non-Sig slots, or a live node.
 */
class N296MergePerInputSigTest {

    private static final String REFERENCE_TX_HEX = "0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdaf064dd10261ab52798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad78820134947f77587f7581788b5679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f7587777747304402206e28a16d52458dfa9cf044624998ec11dd40325cd977f60717b2899140fa5d5c0220254be349dcd9560d14c52b16e427b14ac27617a094eccae4f72431d13b2c18cd4114751e76e8199196d454941c45d1b3a323f1433bd603f3ab014d770301000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd80252798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad78820134947f77587f7581788b5679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f758777776a00000000000000001027000000000000ffffffffe43123bcf4d0eeab865f10e322c4d16fc46b3a43efa7c12fbe647625f43f716b0000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdaf064dd10261ab52798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad78820134947f77587f7581788b5679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f75877777473044022070771db0d862ef7a7f8919ed0cd7651070bca6a2c003e895569541338ba4b4a402205e486cc329e3e31998dedefa9a5901dd2fbdb0e23a29b236130dc958f33e81704114751e76e8199196d454941c45d1b3a323f1433bd603f3ab014d770301000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdd80252798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad78820134947f77587f7581788b5679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f758777776a00000000000000001027000000000000ffffffffe43123bcf4d0eeab865f10e322c4d16fc46b3a43efa7c12fbe647625f43f716b0000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a4730440220573556f2d170f146005aa144fe5648f4b2c18e88dba7464cf887b341f0a15a3c022073c0bd36084ddfd3b8d259d9c2ca07ef05761b119b4abe5aefa5508ef43e527841210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff021027000000000000fdda0261ab52798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad78820134947f77587f7581788b5679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f758777776a0100000000000000f3ab0100000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000";

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

    private static String merge(List<List<Object>> perInputArgs) throws Exception {
        return merge(perInputArgs, null);
    }

    private static String merge(List<List<Object>> perInputArgs, Long feeRate) throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call",
            "stateful-merge-prepared.json");
        Map<String, Object> v = obj(Json.parse(Files.readString(p)));
        StringBuilder artifactJson = new StringBuilder();
        write(artifactJson, v.get("artifact"));
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson.toString());

        UTXO contractUtxo = utxo(v.get("contractUtxo"));
        UTXO extraUtxo = utxo(v.get("extraContractUtxo"));
        UTXO fundingUtxo = utxo(v.get("fundingUtxo"));

        LocalSigner signer = new LocalSigner((String) v.get("privKeyHex"));
        MockProvider provider = new MockProvider();
        if (feeRate != null) provider.setFeeRate(feeRate);
        provider.addUtxo(signer.address(), fundingUtxo);
        provider.addKnownOutpoint(contractUtxo);
        provider.addKnownOutpoint(extraUtxo);
        RunarContract contract = RunarContract.fromUtxo(artifact, contractUtxo);

        List<Object> args = new ArrayList<>();
        args.add(null);
        CallOptions options = new CallOptions(Map.of("count", BigInteger.ONE), null, null, null, null,
            null, null, null, List.of(extraUtxo), perInputArgs);
        RunarContract.CallOutcome out = contract.callWithOptions(
            (String) v.get("method"), args, options, provider, signer);
        return out.rawTxHex();
    }

    /**
     * Fee sizing for a merge: at 1000 sat/kB every byte the fee layout misses
     * is a satoshi under-paid. Each additional contract input's unlock carries
     * {@code _changeAmount}; sizing it with a change of 0 (OP_0) and shipping
     * the real change (a 3-byte script number here) under-paid by 3 sat.
     */
    @Test
    void mergeFeeCoversEveryByteAtOneSatPerByte() throws Exception {
        String hex = merge(null, 1000L);
        RawTx tx = RawTxParser.parse(hex);
        long out = 0;
        for (RawTx.Output o : tx.outputs) out += o.satoshis;
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call",
            "stateful-merge-prepared.json");
        Map<String, Object> v = obj(Json.parse(Files.readString(p)));
        long in = utxo(v.get("contractUtxo")).satoshis() + utxo(v.get("extraContractUtxo")).satoshis()
            + utxo(v.get("fundingUtxo")).satoshis();
        long size = hex.length() / 2;
        org.junit.jupiter.api.Assertions.assertTrue(in - out >= size,
            "paid " + (in - out) + " sat for a " + size + "-byte tx at 1 sat/byte");
    }

    @Test
    void defaultNoOverridePathMatchesTheReferenceTx() throws Exception {
        assertEquals(REFERENCE_TX_HEX, merge(null));
    }

    @Test
    void explicitNonZeroSigInPerInputArgsIsOverwrittenBySigner() throws Exception {
        List<Object> perInput = new ArrayList<>();
        perInput.add("ab".repeat(71));
        assertEquals(REFERENCE_TX_HEX, merge(List.of(perInput)));
    }
}
