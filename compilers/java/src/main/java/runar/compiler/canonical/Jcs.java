package runar.compiler.canonical;

import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import runar.compiler.ir.anf.ConstValue;

/**
 * RFC 8785 / JCS (JSON Canonicalization Scheme) serialiser.
 *
 * <p>Produces a deterministic, byte-identical JSON string for any of
 * the value shapes the Rúnar compiler emits. Reference implementation:
 * {@code packages/runar-ir-schema/src/canonical-json.ts}. The two MUST
 * produce byte-identical output for the same input structures;
 * {@code JcsTest} verifies this against hand-computed expected outputs.
 *
 * <h2>Supported value types</h2>
 * <ul>
 *   <li>{@code null} &rarr; {@code null}</li>
 *   <li>{@link Boolean} &rarr; {@code true} / {@code false}</li>
 *   <li>{@link BigInteger} &rarr; bare JSON integer</li>
 *   <li>{@link String} &rarr; JSON string, escaped per
 *       {@code JSON.stringify} semantics (RFC 8785 §3.2.2.2)</li>
 *   <li>{@link java.util.List} &rarr; JSON array</li>
 *   <li>{@link java.util.Map Map&lt;String, ?&gt;} &rarr; JSON object,
 *       keys sorted by UTF-16 code-unit ordering</li>
 *   <li>{@link Record} &rarr; JSON object built from record components,
 *       keys sorted. Fields whose accessor returns {@code null} are
 *       OMITTED. If the record declares a no-argument {@code kind()}
 *       method (as sealed-interface variants in the Rúnar IR do), its
 *       result is emitted as a synthetic {@code "kind"} field.</li>
 *   <li>{@link ConstValue} &rarr; delegated to {@link ConstValue#raw()}
 *       so that LoadConst wrappers emit the raw value rather than a
 *       nested object.</li>
 * </ul>
 *
 * <p><strong>Not supported</strong> (ANF IR does not use them):
 * {@code double}, {@code float}, {@link Double}, {@link Float}, and any
 * other {@link Number} that is not a {@link BigInteger}. Attempting to
 * serialise such a value throws {@link IllegalArgumentException} —
 * matches the TS "canonical JSON does not support" throw.
 */
public final class Jcs {

    private Jcs() {}

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /** Serialise a value to canonical JSON. */
    public static String stringify(Object value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb, new IdentityHashMap<>());
        return sb.toString();
    }

    // ---------------------------------------------------------------
    // Core dispatch
    // ---------------------------------------------------------------

    private static void write(Object value, StringBuilder sb, IdentityHashMap<Object, Boolean> seen) {
        if (value == null) {
            sb.append("null");
            return;
        }

        if (value instanceof Boolean b) {
            sb.append(b ? "true" : "false");
            return;
        }

        if (value instanceof BigInteger bi) {
            sb.append(bi.toString(10));
            return;
        }

        if (value instanceof String s) {
            writeString(s, sb);
            return;
        }

        if (value instanceof ConstValue cv) {
            write(cv.raw(), sb, seen);
            return;
        }

        if (value instanceof Number) {
            throw new IllegalArgumentException(
                "canonical JSON does not support floating-point numbers (" + value.getClass().getName() + ")"
            );
        }

        if (value instanceof Character) {
            throw new IllegalArgumentException("canonical JSON does not support Character");
        }

        // Collections and records go through cycle detection.
        detectCycle(seen, value);

        if (value instanceof List<?> list) {
            writeArray(list, sb, seen);
        } else if (value instanceof Map<?, ?> map) {
            writeObject(map, sb, seen);
        } else if (value.getClass().isRecord()) {
            writeRecord(value, sb, seen);
        } else if (value instanceof Enum<?> e) {
            // Use a .canonical() accessor if available; otherwise fall
            // back to enum constant name.
            Method m = findNoArgStringMethod(e.getClass(), "canonical");
            if (m != null) {
                try {
                    Object v = m.invoke(e);
                    write(v, sb, seen);
                } catch (ReflectiveOperationException ex) {
                    throw new RuntimeException("failed to invoke canonical() on " + e.getClass().getName(), ex);
                }
            } else {
                writeString(e.name(), sb);
            }
        } else {
            throw new IllegalArgumentException(
                "canonical JSON does not support " + value.getClass().getName()
            );
        }

        seen.remove(value);
    }

    private static void detectCycle(IdentityHashMap<Object, Boolean> seen, Object value) {
        if (seen.put(value, Boolean.TRUE) != null) {
            throw new IllegalArgumentException("canonical JSON does not support circular references");
        }
    }

    // ---------------------------------------------------------------
    // Strings — JSON.stringify-compatible escaping (RFC 8785 §3.2.2.2)
    // ---------------------------------------------------------------

    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        final int len = s.length();
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append("\\u");
                        appendHex4(sb, c);
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static void appendHex4(StringBuilder sb, int v) {
        for (int shift = 12; shift >= 0; shift -= 4) {
            int nibble = (v >> shift) & 0xF;
            sb.append((char) (nibble < 10 ? '0' + nibble : 'a' + nibble - 10));
        }
    }

    // ---------------------------------------------------------------
    // Arrays
    // ---------------------------------------------------------------

    private static void writeArray(List<?> list, StringBuilder sb, IdentityHashMap<Object, Boolean> seen) {
        sb.append('[');
        final int n = list.size();
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(',');
            Object el = list.get(i);
            // Matches JSON.stringify: undefined slots become null.
            if (el == null) {
                sb.append("null");
            } else {
                write(el, sb, seen);
            }
        }
        sb.append(']');
    }

    // ---------------------------------------------------------------
    // Objects (keys sorted by UTF-16 code-unit order == String.compareTo)
    // ---------------------------------------------------------------

    private static void writeObject(Map<?, ?> map, StringBuilder sb, IdentityHashMap<Object, Boolean> seen) {
        List<String> keys = new ArrayList<>(map.size());
        for (Object k : map.keySet()) {
            if (!(k instanceof String sk)) {
                throw new IllegalArgumentException("canonical JSON objects only support String keys (got " + k.getClass().getName() + ")");
            }
            keys.add(sk);
        }
        keys.sort(null);  // natural order = UTF-16 code-unit order

        sb.append('{');
        boolean first = true;
        for (String key : keys) {
            Object val = map.get(key);
            if (val == null) {
                // JSON.stringify omits keys with undefined values.
                continue;
            }
            if (!first) sb.append(',');
            first = false;
            writeString(key, sb);
            sb.append(':');
            write(val, sb, seen);
        }
        sb.append('}');
    }

    // ---------------------------------------------------------------
    // Records — introspective, with optional kind() injection
    // ---------------------------------------------------------------

    private static void writeRecord(Object record, StringBuilder sb, IdentityHashMap<Object, Boolean> seen) {
        Class<?> cls = record.getClass();
        TreeMap<String, Object> map = new TreeMap<>();

        // Inject "kind" if the record declares a no-arg String kind() method.
        // This is how sealed-interface IR variants carry their discriminator
        // without every subclass duplicating a component field.
        Method kindMethod = findNoArgStringMethod(cls, "kind");
        if (kindMethod != null) {
            try {
                Object k = kindMethod.invoke(record);
                if (k != null) {
                    map.put("kind", k);
                }
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException("failed to invoke kind() on " + cls.getName(), e);
            }
        }

        for (RecordComponent rc : cls.getRecordComponents()) {
            Object val;
            try {
                val = rc.getAccessor().invoke(record);
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException("failed to read record component " + rc.getName() + " of " + cls.getName(), e);
            }
            if (val == null) {
                // Matches TS omit-undefined semantics.
                continue;
            }
            JsonName override = rc.getAnnotation(JsonName.class);
            String key = override != null ? override.value() : rc.getName();
            map.put(key, val);
        }

        writeObject(map, sb, seen);
    }

    // ---------------------------------------------------------------
    // Reflection helper
    // ---------------------------------------------------------------

    /** Find a no-argument method on the given class that returns a String, searching up the type hierarchy. */
    private static Method findNoArgStringMethod(Class<?> cls, String name) {
        try {
            Method m = cls.getMethod(name);
            if (m.getParameterCount() == 0 && m.getReturnType() == String.class) {
                return m;
            }
        } catch (NoSuchMethodException ignored) {
            // No such method in the type hierarchy.
        }
        return null;
    }

    // Exposed for test parity with the TS helper.
    public static final Set<Class<?>> SUPPORTED_PRIMITIVES =
        Set.of(Boolean.class, BigInteger.class, String.class);
}
