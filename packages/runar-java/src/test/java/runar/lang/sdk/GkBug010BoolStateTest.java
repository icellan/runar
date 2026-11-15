package runar.lang.sdk;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * GK-BUG-010: a boolean state field accepts only a {@link Boolean}.
 *
 * <p>{@code Boolean.TRUE.equals(value) ? "01" : "00"} silently wrote 00 for
 * Integer 1 and the String "true", while other tiers used truthiness (Ruby
 * wrote 01 for 0): one input, different on-chain bytes per tier. Every tier
 * now refuses a non-boolean, as the num2bin arm (N-084) refuses a non-integer.
 *
 * <p>Proves: {@code StateSerializer.serialize} throws
 * {@code IllegalArgumentException} naming the field and type for null, 0, 1,
 * 1L, 1.0, "true", "false", "" and "01" in both spellings of the type, and
 * TRUE / FALSE keep 01 / 00. Does not prove anything on chain, nor the other
 * six SDKs.
 */
class GkBug010BoolStateTest {

    private static final String[] TYPES = {"bool", "boolean"};

    private static String ser(String type, Object v) {
        Map<String, Object> m = new HashMap<>();
        m.put("flag", v);
        return StateSerializer.serialize(List.of(new StateField("flag", type, 0, null, null)), m);
    }

    @Test
    void refusesNonBoolean() {
        Object[] bad = {null, 0, 1, 1L, 1.0d, "true", "false", "", "01", new Object()};
        for (String type : TYPES) {
            for (Object v : bad) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ser(type, v),
                    type + " " + v);
                String want = "state field \"flag\" (" + type + ") must be a boolean";
                assertTrue(e.getMessage().contains(want), type + " " + v + ": " + e.getMessage());
            }
        }
    }

    @Test
    void trueFalseUnchanged() {
        for (String type : TYPES) {
            assertEquals("01", ser(type, Boolean.TRUE));
            assertEquals("00", ser(type, Boolean.FALSE));
        }
    }

    /**
     * The refusal above must not reject a boolean the SDK computed itself. The
     * language declares {@code bool(x): boolean}, but the ANF interpreter
     * returned BigInteger.ONE / ZERO, so a contract doing
     * {@code this.flag = bool(this.count)} produced a post-state the serializer
     * now refuses (and, before the refusal, silently encoded as 00).
     */
    @Test
    void interpreterComputedBoolSerializes() {
        String json = "{\"contractName\":\"BoolProbe\",\"properties\":["
            + "{\"name\":\"count\",\"type\":\"bigint\",\"readonly\":false},"
            + "{\"name\":\"flag\",\"type\":\"bool\",\"readonly\":false}],"
            + "\"methods\":[{\"name\":\"step\",\"params\":[],\"isPublic\":true,\"body\":["
            + "{\"name\":\"c\",\"value\":{\"kind\":\"load_prop\",\"name\":\"count\"}},"
            + "{\"name\":\"b\",\"value\":{\"kind\":\"call\",\"func\":\"bool\",\"args\":[\"c\"]}},"
            + "{\"name\":\"u\",\"value\":{\"kind\":\"update_prop\",\"name\":\"flag\",\"value\":\"b\"}}]}]}";
        @SuppressWarnings("unchecked")
        Map<String, Object> anf = (Map<String, Object>) Json.parse(json);
        for (long count : new long[] {5L, 0L}) {
            Map<String, Object> st = new HashMap<>();
            st.put("count", java.math.BigInteger.valueOf(count));
            st.put("flag", count == 0L);
            Map<String, Object> out = AnfInterpreter.computeNewState(anf, "step", st, new HashMap<>(), List.of());
            Object flag = out.get("flag");
            assertTrue(flag instanceof Boolean, "count=" + count + ": bool() gave "
                + (flag == null ? "null" : flag.getClass().getSimpleName()));
            assertEquals(count == 0L ? "00" : "01", ser("bool", flag));
        }
    }
}
