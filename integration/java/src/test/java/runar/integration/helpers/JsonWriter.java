package runar.integration.helpers;

import java.util.List;
import java.util.Map;

/**
 * Serialises a value read by {@link JsonReader} back to a JSON string.
 * Only needed because the RPC harness passes JSON fragments between
 * helpers as strings (avoiding a premature commitment to a specific
 * typed representation).
 */
public final class JsonWriter {

    private JsonWriter() {}

    public static String write(Object v) {
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
                sb.append('"').append(escape(String.valueOf(e.getKey()))).append("\":");
                write(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        if (v instanceof List<?> l) {
            sb.append('[');
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) sb.append(',');
                write(sb, l.get(i));
            }
            sb.append(']');
            return;
        }
        if (v instanceof String s) {
            sb.append('"').append(escape(s)).append('"');
            return;
        }
        if (v instanceof Boolean || v instanceof Number) {
            sb.append(v.toString());
            return;
        }
        throw new IllegalArgumentException("JsonWriter: unsupported type " + v.getClass().getName());
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }
}
