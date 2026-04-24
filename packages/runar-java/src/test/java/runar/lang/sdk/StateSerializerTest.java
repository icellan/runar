package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.*;

class StateSerializerTest {

    @Test
    void roundTripsBigIntBoolAndByteStringFields() {
        List<StateField> fields = List.of(
            new StateField("count", "bigint", 0, null, null),
            new StateField("active", "bool", 1, null, null),
            new StateField("owner", "Addr", 2, null, null)
        );
        Map<String, Object> values = Map.of(
            "count", BigInteger.valueOf(42),
            "active", Boolean.TRUE,
            "owner", "aa".repeat(20)
        );

        String hex = StateSerializer.serialize(fields, values);
        assertEquals("2a" + "00".repeat(7) + "01" + "aa".repeat(20), hex);

        Map<String, Object> decoded = StateSerializer.deserialize(fields, hex);
        assertEquals(BigInteger.valueOf(42), decoded.get("count"));
        assertEquals(Boolean.TRUE, decoded.get("active"));
        assertEquals("aa".repeat(20), decoded.get("owner"));
    }

    @Test
    void negativeBigIntEncodesSignMagnitudeInTopBit() {
        List<StateField> fields = List.of(new StateField("n", "bigint", 0, null, null));
        String hex = StateSerializer.serialize(fields, Map.of("n", BigInteger.valueOf(-1)));
        // width=8, abs=1 -> [01, 00..], top bit of last byte sets sign.
        assertEquals("01" + "00".repeat(6) + "80", hex);
        BigInteger decoded = (BigInteger) StateSerializer.deserialize(fields, hex).get("n");
        assertEquals(BigInteger.valueOf(-1), decoded);
    }

    @Test
    void extractFromScriptFindsStateAfterLastOpReturn() {
        // Fake code prefix + OP_RETURN + state (count=1 as 8-byte LE).
        String code = "76a914" + "00".repeat(20) + "88ac";
        String stateHex = "01" + "00".repeat(7);
        String full = code + "6a" + stateHex;

        RunarArtifact art = new RunarArtifact(
            "runar-v0.1.0", "0.1.0", "X",
            new RunarArtifact.ABI(
                new RunarArtifact.ABIConstructor(List.of()),
                List.of()
            ),
            full, "", "2026-01-01T00:00:00Z",
            List.of(new StateField("count", "bigint", 0, null, null)),
            List.of(), List.of(), null, List.of()
        );
        Map<String, Object> s = StateSerializer.extractFromScript(art, full);
        assertNotNull(s);
        assertEquals(BigInteger.ONE, s.get("count"));
    }
}
