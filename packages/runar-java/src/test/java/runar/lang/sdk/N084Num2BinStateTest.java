package runar.lang.sdk;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-084: the num2bin state encode path fails closed.
 *
 * <p>{@code toBigInteger} returned 0 for {@code null}; other bad values only
 * failed incidentally (a {@code NumberFormatException} with no field name, or
 * "unsupported class"). Every non-integer value must be a named refusal.
 *
 * <p>Proves: {@code StateSerializer.serialize} throws
 * {@code IllegalArgumentException} naming the field and type for null, a
 * Boolean, a Double, a byte[], "", a hex string, a non-decimal string and a
 * "+5" string in each of the four num2bin types, and valid integers / decimal
 * integer strings keep their exact bytes. Does not prove anything on chain,
 * nor the other six SDKs.
 */
class N084Num2BinStateTest {

    private static final String[] TYPES = {"int", "bigint", "RabinSig", "RabinPubKey"};

    private static String ser(String type, Object v) {
        Map<String, Object> m = new HashMap<>();
        m.put("k", v);
        return StateSerializer.serialize(List.of(new StateField("k", type, 0, null, null)), m);
    }

    @Test
    void refusesNonInteger() {
        Object[] bad = {null, Boolean.TRUE, 1.5d, 2.0f, new byte[] {1, 2}, "", "deadbeef", "0x10",
            "abc", "abcn", "n", "+5", " 5", new Object()};
        for (String type : TYPES) {
            for (Object v : bad) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ser(type, v));
                String want = "state field \"k\" (" + type + ") must be an integer";
                assertTrue(e.getMessage().contains(want), type + " " + v + ": " + e.getMessage());
            }
        }
    }

    @Test
    void validIntegersUnchanged() {
        Object[][] cases = {
            {0L, "0000000000000000"}, {5L, "0500000000000000"}, {-5L, "0500000000000080"},
            {5, "0500000000000000"}, {BigInteger.valueOf(-5), "0500000000000080"},
            {"5", "0500000000000000"}, {"5n", "0500000000000000"}, {"-5n", "0500000000000080"},
        };
        for (String type : TYPES) {
            for (Object[] c : cases) {
                assertEquals(c[1], ser(type, c[0]), type + " " + c[0]);
            }
        }
    }
}
