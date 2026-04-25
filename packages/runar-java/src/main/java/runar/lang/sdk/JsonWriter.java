package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Minimal hand-rolled JSON serializer for the on-chain providers'
 * request bodies. Mirrors {@link Json} on the read side and
 * deliberately stays stdlib-only.
 *
 * <p>Accepts {@link Map}, {@link List}, {@link String}, {@link Number},
 * {@link Boolean}, and {@code null}. Unknown types raise
 * {@link IllegalArgumentException}.
 */
public final class JsonWriter {
    private JsonWriter() {}

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeString(sb, s);
        } else if (value instanceof Boolean b) {
            sb.append(b ? "true" : "false");
        } else if (value instanceof Long || value instanceof Integer
            || value instanceof Short || value instanceof Byte
            || value instanceof BigInteger) {
            sb.append(value.toString());
        } else if (value instanceof Number n) {
            // Floating point — format without scientific notation for
            // round numbers (matches Bitcoin Core RPC expectations).
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("JsonWriter: non-finite number");
            }
            if (d == Math.floor(d) && !Double.isInfinite(d)) {
                sb.append(Long.toString((long) d));
            } else {
                sb.append(Double.toString(d));
            }
        } else if (value instanceof Map<?, ?> m) {
            writeObject(sb, m);
        } else if (value instanceof List<?> l) {
            writeArray(sb, l);
        } else {
            throw new IllegalArgumentException("JsonWriter: unsupported type " + value.getClass().getName());
        }
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> m) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            Object k = e.getKey();
            if (!(k instanceof String ks)) {
                throw new IllegalArgumentException("JsonWriter: object keys must be strings");
            }
            writeString(sb, ks);
            sb.append(':');
            writeValue(sb, e.getValue());
        }
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, List<?> l) {
        sb.append('[');
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) sb.append(',');
            writeValue(sb, l.get(i));
        }
        sb.append(']');
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
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
