package runar.lang.sdk;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R2-JAVA-JSON: {@link Json} string grammar.
 *
 * <p>readString appended raw U+0000..U+001F, which RFC 8259 forbids inside a
 * string, and handed the four characters after a backslash-u escape to
 * {@code Integer.parseInt(_, 16)}, which also takes a sign (backslash-u+041 =
 * 'A', backslash-u-041 = -65 cast to a char) and non-ASCII Unicode digits. The
 * six peer tiers reject all of these as bad JSON (fixture vectors jj1..jj7).
 *
 * <p>Proves: each malformed spelling throws with a message naming the rule,
 * and the well-formed spellings next to it still parse. Does not prove
 * anything about the other tiers (the shared fixture does that).
 */
class R2JsonStrictnessTest {

    private static String str(String jsonStringLiteral) {
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) Json.parse("{\"a\":" + jsonStringLiteral + "}");
        return (String) m.get("a");
    }

    private static void rejects(String json, String rule) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parse(json),
            "must reject: " + json);
        assertTrue(e.getMessage().contains(rule), "wrong rejection for " + json + ": " + e.getMessage());
    }

    @Test
    void rejectsEveryRawControlCharacterInAString() {
        for (char c = 0; c < 0x20; c++) {
            rejects("{\"a\":\"x" + c + "y\"}", "control character");
            rejects("{\"k" + c + "\":1}", "control character");
        }
    }

    @Test
    void rejectsUnicodeEscapesThatAreNotFourAsciiHexDigits() {
        for (String esc : List.of("\\u+041", "\\u-041", "\\u\uff10\uff1041", "\\u12G4", "\\u 041", "\\u0x41")) {
            rejects("{\"a\":\"" + esc + "\"}", "\\u escape");
        }
        rejects("{\"a\":\"\\u041\"}", "\\u escape");
        rejects("{\"a\":\"\\u04", "\\u escape");
    }

    @Test
    void keepsWellFormedStrings() {
        assertEquals("A", str("\"\\u0041\""));
        assertEquals("\u00e9", str("\"\\u00E9\""));
        assertEquals("\u0001\t\n", str("\"\\u0001\\t\\n\""));
        assertEquals("\uD83D\uDE00", str("\"\\ud83d\\ude00\""));
        assertEquals("x\u007fy", str("\"x\u007fy\"")); // DEL is not a JSON control character
        assertEquals("\u00e9", str("\"\u00e9\""));
    }
}
