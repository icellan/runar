package runar.lang.sdk;

import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * GK-BUG-009 (number grammar): {@link Json#parse} must accept exactly the
 * RFC 8259 number grammar, {@code -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?}.
 *
 * <p>readNumber used to collect any run of digits, '.', 'e', '+', '-' and
 * hand it to Long.parseLong / Double.parseDouble, so {@code 01} parsed as 1
 * and {@code 1.} as 1.0. The six peer tiers reject both as bad JSON, so a
 * signed envelope with {@code "nonce":01} verified ok in Java alone
 * (fixture vector nt1).
 *
 * <p>Proves: the malformed spellings throw and every well-formed spelling
 * still parses to the same Long / Double / BigInteger as before. Does not
 * prove string-grammar strictness (raw control characters, see open issues).
 */
class GkBug009JsonNumberGrammarTest {

    private static Object num(String tok) {
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) Json.parse("{\"a\":" + tok + "}");
        return m.get("a");
    }

    @Test
    void rejectsMalformedNumberTokens() {
        for (String tok : new String[] {
            "01", "-01", "00", "1.", "-1.", ".5", "-", "1e", "1e+", "1E-", "1.e3",
            "1-2", "1+2", "--1", "1e3e4", "1.2.3", "-.5",
        }) {
            assertThrows(IllegalArgumentException.class, () -> num(tok), "token " + tok + " must be rejected");
        }
    }

    @Test
    void keepsWellFormedNumberTokens() {
        assertEquals(0L, num("0"));
        assertEquals(0L, num("-0"));
        assertEquals(7L, num("7"));
        assertEquals(-12L, num("-12"));
        assertEquals(9223372036854775807L, num("9223372036854775807"));
        assertEquals(new java.math.BigInteger("18446744073709551617"), num("18446744073709551617"));
        assertEquals(1.5, num("1.5"));
        assertEquals(0.25, num("0.25"));
        assertEquals(1000.0, num("1e3"));
        assertEquals(1000.0, num("1E+3"));
        assertEquals(-0.0015, num("-1.5e-3"));
        assertEquals(1.0, num("1.0"));
    }
}
