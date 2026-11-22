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
 * (reference below was Spend-validated by the TS MockProvider on both inputs; re-derived through
 * TS prepareCall/finalizeCall after D25 moved the vector's MergeCounter artifact), and a call
 * with changeAddress alone for another key is refused with the shared N-426 message and
 * nothing is broadcast. Does not prove: a live node, the terminal path, or Java-side script execution
 * (Java has no ScriptVM; validity rests on the TS-validated reference).
 */
class N425StatefulChangeAddressTest {

    private static final String SIGHASH = "251ba24dc4f7aa4d4e84f312bfd8e427cd46b84c48eb8578f247668ba9c4de65";
    private static final String SIG = "3045022100d3f99863e6e3a7d3e33840f0fd01fc1b32c194ddcbe3466882dfb6f32a9f3a9d02202f4767641f9385a9ef9834f63925db825cab9946196abeb47b8ae5504ca9c39e41";
    private static final String ADDR_B = "1KvP21twgz7RTnDbAztPGTjx3YCAk3Evpu";
    private static final String PUB_B = "023ef30130654689a64c864d6dd38760481c55fc525e2c6c7084e2d2d3d4d51be9";
    private static final String REFERENCE_TX_HEX = ""
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
        + "77687eaa7b820128947f7701207f75877777483045022100d3f99863e6e3a7d3e33840f0fd01fc1b32c194ddcbe3466882df"
        + "b6f32a9f3a9d02202f4767641f9385a9ef9834f63925db825cab9946196abeb47b8ae5504ca9c39e4114cf8ab07ab8fdf651"
        + "836592492b9b036b7ca0c906039385014d770301000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438"
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
        + "000000001027000000000000ffffffff1b1ef304ee2aea74ed50fe10ea8f4d011ffc42bff1daacebb41430975dbd77840000"
        + "000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a473044"
        + "02200d976977670287d5ac2372ff93f35b8ba2019b090b39f3be61893bbf6c66673902201499b5c3131180923b08c6a01a3f"
        + "4dafe0d7464ebc43aeaba5662e204d00690541210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16"
        + "f81798ffffffff021027000000000000fdda0261ab52798201149d757676aa517f517f517f517f517f517f517f517f517f51"
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
        + "9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f758777776a010000000000000093"
        + "850100000000001976a914cf8ab07ab8fdf651836592492b9b036b7ca0c90688ac00000000";

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
