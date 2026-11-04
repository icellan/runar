package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
 * N-425: the stateful (OP_PUSH_TX) call path honours {@link CallOptions#changeAddress}
 * and {@link CallOptions#changePubKey} exactly as the TS SDK does
 * (packages/runar-sdk/src/contract.ts): the P2PKH change OUTPUT pays
 * {@code options.changeAddress ?? signer address}, and the covenant's {@code _changePKH}
 * unlock argument is {@code hash160(options.changePubKey ?? signer pubkey)}. The two are
 * independent options; the covenant rebuilds the change output from {@code _changePKH}, so a
 * spend is valid only when they name the same key (measured on TS: changeAddress alone
 * builds a tx @bsv/sdk Spend rejects; changeAddress + matching changePubKey is accepted).
 * Go, Rust and Python carry the same two options. N-426 (R164): changeAddress alone for another
 * key is now refused before signing/broadcast in every SDK, so that case asserts the refusal.
 *
 * <p>Proves: given the MergeCounter stateful vector's artifact/UTXOs/key
 * ({@code conformance/sdk-call/stateful-merge-prepared.json}), a call with
 * changeAddress + changePubKey of a second key reproduces the TS tx byte for byte
 * (reference below was Spend-validated by the TS MockProvider on both inputs), and a call
 * with changeAddress alone for another key is refused with the shared N-426 message and
 * nothing is broadcast. Does not prove: a live node, the terminal path, or Java-side script execution
 * (Java has no ScriptVM; validity rests on the TS-validated reference).
 */
class N425StatefulChangeAddressTest {

    private static final String SIGHASH = "b8b85a722c05efc55e4af8718b3762c5859627209f59d4c84e0e55643f80a067";
    private static final String SIG = "3044022000adf8e9c0ba44d334090a4e8e0cc3ebded94b525d522b63602f0527510b742502204ee41770b910663f1f5e49fe1532c817133f8831d5b13240857f10f4ea159a3c41";
    private static final String ADDR_B = "1KvP21twgz7RTnDbAztPGTjx3YCAk3Evpu";
    private static final String PUB_B = "023ef30130654689a64c864d6dd38760481c55fc525e2c6c7084e2d2d3d4d51be9";
    private static final String REFERENCE_TX_HEX = ""
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
        + "7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777473044022000adf8e9c0ba44d334090a4e8e0cc3ebded94b52"
        + "5d522b63602f0527510b742502204ee41770b910663f1f5e49fe1532c817133f8831d5b13240857f10f4ea159a3c4114cf8a"
        + "b07ab8fdf651836592492b9b036b7ca0c906039085010210274d7e0301000000ef9b6802354444eada24842d68525e3b2860"
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
        + "0128947f7701207f7587776a00000000000000001027000000000000ffffffffeef483e07bc9bf6d79b5bdfebadb047ac600"
        + "d78e456622465f96ed3b16e388c60000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        + "bbbbbbbbbbbbbbbb000000006a47304402207321b4dd5df7c5a11803b59d51a3cfcfe3be83899b761a9c1c79194b2888bba7"
        + "022062bcc245bef35da97b4bd4a6e36055a6e4cf21c1f01ff8a1deeea590e8e6e17241210279be667ef9dcbbac55a06295ce"
        + "870b07029bfcdb2dce28d959f2815b16f81798ffffffff021027000000000000fde10261ab7676aa517f517f517f517f517f"
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
        + "7c820128947f7701207f7587776a010000000000000090850100000000001976a914cf8ab07ab8fdf651836592492b9b036b"
        + "7ca0c90688ac00000000";

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

    private record Fixture(RunarContract contract, MockProvider provider, LocalSigner signer) {}

    private static Fixture fresh() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-call",
            "stateful-merge-prepared.json");
        Map<String, Object> v = obj(Json.parse(Files.readString(p)));
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

    private static String p2pkhHex(String pubKeyHex) {
        return "76a914" + ScriptUtils.bytesToHex(Hash160.hash160(ScriptUtils.hexToBytes(pubKeyHex))) + "88ac";
    }

    @Test
    void changeAddressWithChangePubKeyReproducesTheSpendValidatedTsTx() throws Exception {
        Fixture f = fresh();
        CallOptions options = new CallOptions(null, null, null).withChangeAddress(ADDR_B).withChangePubKey(PUB_B);
        PreparedCall prepared = prepare(f, options);
        assertEquals(SIGHASH, ScriptUtils.bytesToHex(prepared.sighashes().get(0)));
        byte[] der = ScriptUtils.hexToBytes(SIG.substring(0, SIG.length() - 2));
        RunarContract.CallOutcome out = f.contract().finalizeCall(prepared, List.of(der), f.provider());
        assertEquals(REFERENCE_TX_HEX, out.rawTxHex(),
            "changeAddress + changePubKey must emit the TS reference tx");
    }

    @Test
    void changeAddressAloneForAnotherKeyIsRefusedBeforeAnyBroadcast() throws Exception {
        // N-426 (R164): changeAddress alone for a key other than the signer builds a spend the
        // network rejects (the covenant's _changePKH stays the signer's), so it is refused.
        Fixture f = fresh();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> prepare(f, new CallOptions(null, null, null).withChangeAddress(ADDR_B)));
        assertEquals(ScriptUtils.changeAddressMismatchMessage(ADDR_B), e.getMessage());
        assertEquals(0, f.provider().getBroadcastedTxs().size());
        PreparedCall defaults = prepare(fresh(), null);
        String signerPkh = p2pkhHex(ScriptUtils.bytesToHex(f.signer().pubKey()));
        assertTrue(defaults.txHex().contains(signerPkh), "default change pays the signer");
        assertFalse(defaults.txHex().contains(p2pkhHex(PUB_B)));
    }
}
