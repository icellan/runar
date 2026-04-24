package runar.integration.helpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON parser used by the integration test harness. Mirrors the
 * feature set of {@code packages/runar-java/src/main/java/runar/lang/sdk/Json.java}
 * (which is package-private and cannot be shared across modules).
 *
 * <p>Supports: objects, arrays, strings, numbers ({@link Long} for
 * integers, {@link Double} for decimals), booleans, and null. Unicode
 * escapes are decoded. This is intentionally lax — the integration
 * harness only feeds it output from bitcoind / Teranode / the
 * {@code runar-java} compiler, all of which produce well-formed JSON.
 */
public final class JsonReader {

    private final String src;
    private int pos;

    public JsonReader(String src) {
        this.src = src;
        this.pos = 0;
    }

    public Object readValue() {
        skipWs();
        if (pos >= src.length()) throw new IllegalStateException("JsonReader: empty input");
        char c = src.charAt(pos);
        return switch (c) {
            case '{' -> readObject();
            case '[' -> readArray();
            case '"' -> readString();
            case 't', 'f' -> readBool();
            case 'n' -> readNull();
            default -> readNumber();
        };
    }

    private Map<String, Object> readObject() {
        Map<String, Object> m = new LinkedHashMap<>();
        expect('{');
        skipWs();
        if (peek() == '}') { pos++; return m; }
        while (true) {
            skipWs();
            String key = readString();
            skipWs();
            expect(':');
            Object value = readValue();
            m.put(key, value);
            skipWs();
            char c = src.charAt(pos++);
            if (c == '}') return m;
            if (c != ',') throw new IllegalStateException(
                "JsonReader: expected ',' or '}' at " + pos);
        }
    }

    private List<Object> readArray() {
        List<Object> list = new ArrayList<>();
        expect('[');
        skipWs();
        if (peek() == ']') { pos++; return list; }
        while (true) {
            Object v = readValue();
            list.add(v);
            skipWs();
            char c = src.charAt(pos++);
            if (c == ']') return list;
            if (c != ',') throw new IllegalStateException(
                "JsonReader: expected ',' or ']' at " + pos);
        }
    }

    private String readString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (pos < src.length()) {
            char c = src.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                if (pos >= src.length()) throw new IllegalStateException("JsonReader: EOF in escape");
                char esc = src.charAt(pos++);
                switch (esc) {
                    case '"', '\\', '/' -> sb.append(esc);
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > src.length())
                            throw new IllegalStateException("JsonReader: truncated \\u escape");
                        int cp = Integer.parseInt(src.substring(pos, pos + 4), 16);
                        sb.append((char) cp);
                        pos += 4;
                    }
                    default -> throw new IllegalStateException("JsonReader: bad escape \\" + esc);
                }
            } else {
                sb.append(c);
            }
        }
        throw new IllegalStateException("JsonReader: unterminated string");
    }

    private Boolean readBool() {
        if (src.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
        if (src.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
        throw new IllegalStateException("JsonReader: expected true/false at " + pos);
    }

    private Object readNull() {
        if (src.startsWith("null", pos)) { pos += 4; return null; }
        throw new IllegalStateException("JsonReader: expected null at " + pos);
    }

    private Number readNumber() {
        int start = pos;
        if (peek() == '-') pos++;
        while (pos < src.length() && "0123456789".indexOf(src.charAt(pos)) >= 0) pos++;
        boolean isFloat = false;
        if (pos < src.length() && src.charAt(pos) == '.') {
            isFloat = true;
            pos++;
            while (pos < src.length() && "0123456789".indexOf(src.charAt(pos)) >= 0) pos++;
        }
        if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
            isFloat = true;
            pos++;
            if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
            while (pos < src.length() && "0123456789".indexOf(src.charAt(pos)) >= 0) pos++;
        }
        String num = src.substring(start, pos);
        if (isFloat) return Double.valueOf(num);
        return Long.valueOf(num);
    }

    private void skipWs() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
            else break;
        }
    }

    private char peek() {
        if (pos >= src.length()) throw new IllegalStateException("JsonReader: EOF");
        return src.charAt(pos);
    }

    private void expect(char c) {
        if (pos >= src.length() || src.charAt(pos) != c) {
            throw new IllegalStateException("JsonReader: expected '" + c + "' at " + pos);
        }
        pos++;
    }
}
