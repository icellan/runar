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
 * loading {@link RunarArtifact} fixtures. Not RFC 8259 complete
 * (does not support scientific notation or surrogate pairs in
 * escapes), which is all the artifact shape needs.
 */
public final class Json {
    private Json() {}

    public static Object parse(String input) {
        Parser p = new Parser(input);
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
        int pos = 0;

        Parser(String s) { this.s = s; }

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
                String key = readString();
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
                            if (pos + 4 > s.length()) {
                                throw new IllegalArgumentException("Json: bad \\u escape");
                            }
                            int cp = Integer.parseInt(s.substring(pos, pos + 4), 16);
                            pos += 4;
                            sb.append((char) cp);
                        }
                        default -> throw new IllegalArgumentException("Json: unknown escape \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Json: unterminated string");
        }

        Object readNumber() {
            int start = pos;
            if (peek() == '-') pos++;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    pos++;
                } else break;
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
