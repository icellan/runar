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
}
