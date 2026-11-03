package runar.lang.sdk;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-045 (EXT-2 WideHash), SDK side — defence in depth only.
 *
 * <p>The on-chain state reader slices each fixed-width byte field at its
 * declared width, so a wrong-width value in a state section shifts every later
 * field. The consensus defence is the covenant's own
 * {@code OP_SIZE <width> OP_NUMEQUALVERIFY} before each continuation commit
 * (proved under strict Spend in
 * packages/runar-testing/src/__tests__/n045-state-fixed-width-spend.test.ts).
 * These tests pin the off-chain refusals: {@code StateSerializer.serialize},
 * {@code call} and {@code prepareCall} reject a wrong-width fixed-width value.
 * (Constructor args are deliberately NOT checked: {@code fromUtxo} builds its
 * contract with placeholder constructor args. A mutable field's deploy-time
 * value still goes through the state serializer.) They prove nothing on chain.
 */
class N045FixedWidthTest {

    private static final Object[][] TYPES = {
        {"PubKey", 33}, {"Sha256", 32}, {"Ripemd160", 20}, {"Addr", 20},
        {"Point", 64}, {"P256Point", 64}, {"P384Point", 96},
    };

    @Test
    void serializeRefusesWrongWidthAndAcceptsExactWidth() {
        for (Object[] t : TYPES) {
            String type = (String) t[0];
            int width = (Integer) t[1];
            List<StateField> fields = List.of(new StateField("k", type, 0, null, null));
            for (int bad : new int[] {width - 1, width + 1}) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> StateSerializer.serialize(fields, Map.of("k", "ab".repeat(bad))));
                assertTrue(e.getMessage().contains("must be exactly " + width + " bytes"), e.getMessage());
            }
            IllegalArgumentException nh = assertThrows(IllegalArgumentException.class,
                () -> StateSerializer.serialize(fields, Map.of("k", "zz".repeat(width))));
            assertTrue(nh.getMessage().contains("non-hex"), nh.getMessage());
            assertEquals("ab".repeat(width), StateSerializer.serialize(fields, Map.of("k", "ab".repeat(width))));
        }
    }

    private static RunarArtifact rootArtifact() {
        String json =
            "{"
            + "\"version\":\"runar-v0.1.0\","
            + "\"compilerVersion\":\"0.1.0\","
            + "\"contractName\":\"N045Root\","
            + "\"script\":\"51\","
            + "\"asm\":\"\","
            + "\"abi\":{"
                + "\"constructor\":{\"params\":[{\"name\":\"root\",\"type\":\"Sha256\"}]},"
                + "\"methods\":[{\"name\":\"updateRoot\",\"isPublic\":true,\"params\":["
                    + "{\"name\":\"nextRoot\",\"type\":\"Sha256\"}"
                + "]}]"
            + "},"
            + "\"buildTimestamp\":\"2026-10-04T00:00:00.000Z\""
            + "}";
        return RunarArtifact.fromJson(json);
    }

    @Test
    void callAndPrepareCallRefuseWrongWidthSha256Arg() {
        for (int bad : new int[] {31, 33, 66}) {
            RunarContract contract = new RunarContract(rootArtifact(), List.of("11".repeat(32)));
            contract.setCurrentUtxo(new UTXO("ab".repeat(32), 0, 10_000L, "51"));
            MockProvider provider = new MockProvider();
            IllegalArgumentException p = assertThrows(IllegalArgumentException.class,
                () -> contract.prepareCall("updateRoot", List.of("22".repeat(bad)), null, provider, new MockSigner()));
            assertTrue(p.getMessage().contains("arg 'nextRoot' (index 0)")
                && p.getMessage().contains("must be exactly 32 bytes"), p.getMessage());
            IllegalArgumentException c = assertThrows(IllegalArgumentException.class,
                () -> contract.call("updateRoot", List.of("22".repeat(bad)), null, provider, new MockSigner()));
            assertTrue(c.getMessage().contains("arg 'nextRoot' (index 0)")
                && c.getMessage().contains("must be exactly 32 bytes"), c.getMessage());
        }
    }
}
