package runar.sdkdriver;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tiny JSON parser + serializer tailored for the conformance driver
 * input shape. Not a general-purpose library — deliberately minimal to
 * avoid pulling Jackson or Gson into the driver classpath.
 *
 * <p>The parser accepts objects, arrays, strings, booleans, null, and
 * integers. Numbers with a fraction or exponent are returned as
 * {@link String} so downstream BigInteger conversion never loses
 * precision. The serializer is used to re-encode the parsed artifact
 * map so the Java SDK's internal {@code Json} parser can re-read it.
 */
final class MiniJson {
    private MiniJson() {}

    // ------------------------------------------------------------------
    // Parse
    // ------------------------------------------------------------------

    static Object parse(String s) {
        Parser p = new Parser(s);
        p.skipWs();
        Object v = p.readValue();
        p.skipWs();
        if (p.pos != s.length()) {
            throw new IllegalArgumentException("trailing garbage at " + p.pos);
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asObject(Object v) {
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("expected object");
        }
        return (Map<String, Object>) v;
    }

    static String asString(Object v) {
        if (v == null) return null;
        return v instanceof String s ? s : v.toString();
    }

    private static final class Parser {
        final String src;
        int pos;

        Parser(String src) { this.src = src; }

        void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') pos++;
                else break;
            }
        }

        Object readValue() {
            skipWs();
            if (pos >= src.length()) throw new IllegalArgumentException("eof");
            char c = src.charAt(pos);
            if (c == '{') return readObject();
            if (c == '[') return readArray();
            if (c == '"') return readString();
            if (c == 't' || c == 'f') return readBool();
            if (c == 'n') { expect("null"); return null; }
            return readNumber();
        }

        Map<String, Object> readObject() {
            expect("{");
            Map<String, Object> out = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { pos++; return out; }
            while (true) {
                skipWs();
                String key = readString();
                skipWs();
                expect(":");
                Object val = readValue();
                out.put(key, val);
                skipWs();
                char c = src.charAt(pos++);
                if (c == ',') continue;
                if (c == '}') break;
                throw new IllegalArgumentException("expected , or } at " + (pos - 1));
            }
            return out;
        }

        List<Object> readArray() {
            expect("[");
            List<Object> out = new ArrayList<>();
            skipWs();
            if (peek() == ']') { pos++; return out; }
            while (true) {
                out.add(readValue());
                skipWs();
                char c = src.charAt(pos++);
                if (c == ',') continue;
                if (c == ']') break;
                throw new IllegalArgumentException("expected , or ] at " + (pos - 1));
            }
            return out;
        }

        String readString() {
            skipWs();
            if (src.charAt(pos) != '"') {
                throw new IllegalArgumentException("expected string at " + pos);
            }
            pos++;
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char esc = src.charAt(pos++);
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            int code = Integer.parseInt(src.substring(pos, pos + 4), 16);
                            sb.append((char) code);
                            pos += 4;
                        }
                        default -> throw new IllegalArgumentException("bad escape \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("unterminated string");
        }

        Boolean readBool() {
            if (src.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
            if (src.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
            throw new IllegalArgumentException("expected bool at " + pos);
        }

        Object readNumber() {
            int start = pos;
            if (src.charAt(pos) == '-') pos++;
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    pos++;
                } else {
                    break;
                }
            }
            String num = src.substring(start, pos);
            if (num.indexOf('.') < 0 && num.indexOf('e') < 0 && num.indexOf('E') < 0) {
                try {
                    long l = Long.parseLong(num);
                    return l;
                } catch (NumberFormatException e) {
                    return new BigInteger(num);
                }
            }
            // Preserve fractional numbers as string; artifact fields don't use them.
            return num;
        }

        void expect(String lit) {
            if (!src.startsWith(lit, pos)) {
                throw new IllegalArgumentException("expected '" + lit + "' at " + pos);
            }
            pos += lit.length();
        }

        char peek() {
            skipWs();
            return src.charAt(pos);
        }
    }

    // ------------------------------------------------------------------
    // Serialize
    // ------------------------------------------------------------------

    static String toJson(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        if (v instanceof List<?> l) {
            sb.append('[');
            boolean first = true;
            for (Object o : l) {
                if (!first) sb.append(',');
                first = false;
                write(sb, o);
            }
            sb.append(']');
            return;
        }
        if (v instanceof String s) { writeString(sb, s); return; }
        if (v instanceof Boolean b) { sb.append(b); return; }
        if (v instanceof Number) { sb.append(v); return; }
        writeString(sb, v.toString());
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }
}
