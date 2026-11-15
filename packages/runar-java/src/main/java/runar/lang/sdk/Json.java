package runar.lang.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal hand-rolled JSON parser. Returns a generic value tree of:
 * <ul>
 *     <li>{@link Map}&lt;String, Object&gt; for objects (ordered)</li>
 *     <li>{@link List}&lt;Object&gt; for arrays</li>
 *     <li>{@link String} for strings</li>
 *     <li>{@link Long} for integers that fit</li>
 *     <li>{@link java.math.BigInteger} for integers that don't</li>
 *     <li>{@link Double} for non-integer numbers</li>
 *     <li>{@link Boolean} for {@code true}/{@code false}</li>
 *     <li>{@code null} for JSON {@code null}</li>
 * </ul>
 *
 * <p>Deliberately stdlib-only — no Jackson, no Gson. Sufficient for
 * loading {@link RunarArtifact} fixtures and the signed-envelope payload.
 * Strings follow the RFC 8259 grammar (raw U+0000..U+001F and malformed
 * escapes are rejected, R2-JAVA-JSON); a surrogate-pair escape is kept as
 * its two UTF-16 units, which is the same Java string as the raw code point.
 */
public final class Json {
    private Json() {}

    public static Object parse(String input) {
        return parse(input, false);
    }

    /**
     * {@link #parse}, but an object that carries the same key twice (compared
     * after unescaping) throws instead of keeping the last value. R2-DUPKEY:
     * the signed-envelope payload parser. Artifact loading keeps
     * {@link #parse}'s keep-last behaviour.
     */
    static Object parseRejectingDuplicateKeys(String input) {
        return parse(input, true);
    }

    private static Object parse(String input, boolean rejectDuplicateKeys) {
        Parser p = new Parser(input, rejectDuplicateKeys);
        p.skipWs();
        Object result = p.readValue();
        p.skipWs();
        if (p.pos != input.length()) {
            throw new IllegalArgumentException("Json: trailing garbage at offset " + p.pos);
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asObject(Object v) {
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("expected JSON object, got " + type(v));
        }
        return (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    static List<Object> asArray(Object v) {
        if (!(v instanceof List)) {
            throw new IllegalArgumentException("expected JSON array, got " + type(v));
        }
        return (List<Object>) v;
    }

    static String asString(Object v) {
        if (v == null) return null;
        if (v instanceof String s) return s;
        throw new IllegalArgumentException("expected JSON string, got " + type(v));
    }

    static long asLong(Object v) {
        if (v instanceof Long l) return l;
        if (v instanceof Integer i) return i;
        if (v instanceof java.math.BigInteger bi) return bi.longValueExact();
        if (v instanceof Double d) return d.longValue();
        throw new IllegalArgumentException("expected JSON integer, got " + type(v));
    }

    static int asInt(Object v) {
        return Math.toIntExact(asLong(v));
    }

    static boolean asBool(Object v) {
        if (v instanceof Boolean b) return b;
        throw new IllegalArgumentException("expected JSON boolean, got " + type(v));
    }

    private static String type(Object v) {
        if (v == null) return "null";
        return v.getClass().getSimpleName();
    }

    // ------------------------------------------------------------------

    private static final class Parser {
        private final String s;
        private final boolean rejectDuplicateKeys;
        int pos = 0;

        Parser(String s, boolean rejectDuplicateKeys) {
            this.s = s;
            this.rejectDuplicateKeys = rejectDuplicateKeys;
        }

        void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object readValue() {
            skipWs();
            if (pos >= s.length()) throw new IllegalArgumentException("Json: unexpected EOF");
            char c = s.charAt(pos);
            if (c == '{') return readObject();
            if (c == '[') return readArray();
            if (c == '"') return readString();
            if (c == '-' || (c >= '0' && c <= '9')) return readNumber();
            if (s.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
            if (s.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
            if (s.startsWith("null", pos)) { pos += 4; return null; }
            throw new IllegalArgumentException("Json: unexpected character at " + pos + ": " + c);
        }

        Map<String, Object> readObject() {
            expect('{');
            Map<String, Object> out = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { pos++; return out; }
            while (true) {
                skipWs();
                int keyAt = pos;
                String key = readString();
                if (rejectDuplicateKeys && out.containsKey(key)) {
                    throw new IllegalArgumentException("Json: duplicate key \"" + key + "\" at " + keyAt);
                }
                skipWs();
                expect(':');
                Object val = readValue();
                out.put(key, val);
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; return out; }
                throw new IllegalArgumentException("Json: expected ',' or '}' at " + pos);
            }
        }

        List<Object> readArray() {
            expect('[');
            List<Object> out = new ArrayList<>();
            skipWs();
            if (peek() == ']') { pos++; return out; }
            while (true) {
                out.add(readValue());
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; return out; }
                throw new IllegalArgumentException("Json: expected ',' or ']' at " + pos);
            }
        }

        String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= s.length()) throw new IllegalArgumentException("Json: bad escape at EOF");
                    char esc = s.charAt(pos++);
                    switch (esc) {
                        case '"', '\\', '/' -> sb.append(esc);
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            // R2-JAVA-JSON: exactly four ASCII hex digits.
                            // Integer.parseInt(_, 16) also took a sign
                            // (backslash-u+041 = 'A') and non-ASCII Unicode
                            // digits; every peer tier rejects both.
                            if (pos + 4 > s.length()) {
                                throw new IllegalArgumentException("Json: bad \\u escape at " + (pos - 2));
                            }
                            int cp = 0;
                            for (int k = 0; k < 4; k++) {
                                int d = hexDigit(s.charAt(pos + k));
                                if (d < 0) {
                                    throw new IllegalArgumentException("Json: bad \\u escape at " + (pos - 2));
                                }
                                cp = (cp << 4) | d;
                            }
                            pos += 4;
                            sb.append((char) cp);
                        }
                        default -> throw new IllegalArgumentException("Json: unknown escape \\" + esc);
                    }
                } else if (c < 0x20) {
                    // R2-JAVA-JSON: RFC 8259 requires U+0000..U+001F to be
                    // escaped inside a string; every peer tier rejects them raw.
                    throw new IllegalArgumentException(String.format(
                        "Json: unescaped control character U+%04X in string at %d", (int) c, pos - 1));
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Json: unterminated string");
        }

        // GK-BUG-009: exactly the RFC 8259 grammar
        //   -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
        // The old loop took any run of [0-9.eE+-], so 01 became Long 1 and 1.
        // became 1.0; every peer tier rejects both as bad JSON, so a signed
        // envelope with "nonce":01 verified ok in this tier alone.
        Object readNumber() {
            int start = pos;
            if (peek() == '-') pos++;
            if (peek() == '0') {
                pos++;
            } else if (peek() >= '1' && peek() <= '9') {
                skipDigits();
            } else {
                throw new IllegalArgumentException("Json: bad number at " + start);
            }
            if (peek() == '.') {
                pos++;
                if (!(peek() >= '0' && peek() <= '9')) {
                    throw new IllegalArgumentException("Json: bad number fraction at " + start);
                }
                skipDigits();
            }
            if (peek() == 'e' || peek() == 'E') {
                pos++;
                if (peek() == '+' || peek() == '-') pos++;
                if (!(peek() >= '0' && peek() <= '9')) {
                    throw new IllegalArgumentException("Json: bad number exponent at " + start);
                }
                skipDigits();
            }
            String tok = s.substring(start, pos);
            if (tok.contains(".") || tok.contains("e") || tok.contains("E")) {
                return Double.parseDouble(tok);
            }
            try {
                return Long.parseLong(tok);
            } catch (NumberFormatException nfe) {
                return new java.math.BigInteger(tok);
            }
        }

        private static int hexDigit(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        void skipDigits() {
            while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') pos++;
        }

        char peek() {
            if (pos >= s.length()) return '\0';
            return s.charAt(pos);
        }

        void expect(char c) {
            if (pos >= s.length() || s.charAt(pos) != c) {
                throw new IllegalArgumentException("Json: expected '" + c + "' at " + pos);
            }
            pos++;
        }
    }
}
