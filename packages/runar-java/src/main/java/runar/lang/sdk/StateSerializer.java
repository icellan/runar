package runar.lang.sdk;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import runar.lang.sdk.RunarArtifact.FixedArrayMeta;
import runar.lang.sdk.RunarArtifact.StateField;

/**
 * Encodes / decodes contract state as Bitcoin Script push-data after
 * an OP_RETURN separator. Parity with
 * {@code packages/runar-go/sdk_state.go}.
 *
 * <p>Values passed to {@link #serialize(List, Map)} can be
 * {@link BigInteger}, {@link Long}, {@link Integer}, {@link Boolean},
 * or a hex string for fixed-size byte types. {@link #deserialize(List, String)}
 * returns {@link BigInteger} for {@code int}/{@code bigint},
 * {@link Boolean} for {@code bool}, and hex strings for byte types.
 */
public final class StateSerializer {

    private StateSerializer() {}

    /**
     * Serialises state values to raw hex bytes (no OP_RETURN prefix).
     * Fields are emitted in {@link StateField#index()} order.
     */
    public static String serialize(List<StateField> fields, Map<String, Object> values) {
        List<StateField> sorted = new ArrayList<>(fields);
        sorted.sort(Comparator.comparingInt(StateField::index));
        StringBuilder sb = new StringBuilder();
        for (StateField f : sorted) {
            if (f.fixedArray() != null) {
                FixedArrayMeta fa = f.fixedArray();
                String leafType = unwrapFixedArrayLeaf(f.type());
                List<Integer> dims = parseFixedArrayDims(f.type());
                List<Object> flatFromArr = null;
                if (values.containsKey(f.name())) {
                    flatFromArr = flattenNestedValue(values.get(f.name()), dims);
                }
                for (int i = 0; i < fa.syntheticNames().size(); i++) {
                    String synth = fa.syntheticNames().get(i);
                    Object elem = values.containsKey(synth)
                        ? values.get(synth)
                        : (flatFromArr != null && i < flatFromArr.size() ? flatFromArr.get(i) : null);
                    sb.append(encodeStateValue(elem, leafType));
                }
            } else {
                sb.append(encodeStateValue(values.get(f.name()), f.type()));
            }
        }
        return sb.toString();
    }

    /**
     * Deserialises state from the raw hex bytes between the OP_RETURN
     * separator and the end of the script.
     */
    public static Map<String, Object> deserialize(List<StateField> fields, String scriptHex) {
        List<StateField> sorted = new ArrayList<>(fields);
        sorted.sort(Comparator.comparingInt(StateField::index));
        Map<String, Object> out = new LinkedHashMap<>();
        int[] offset = {0};
        for (StateField f : sorted) {
            if (f.fixedArray() != null) {
                String leafType = unwrapFixedArrayLeaf(f.type());
                List<Integer> dims = parseFixedArrayDims(f.type());
                int total = f.fixedArray().syntheticNames().size();
                List<Object> flat = new ArrayList<>(total);
                for (int i = 0; i < total; i++) {
                    Object v = decodeStateValue(scriptHex, offset, leafType);
                    flat.add(v);
                }
                out.put(f.name(), regroupNestedValue(flat, dims));
            } else {
                out.put(f.name(), decodeStateValue(scriptHex, offset, f.type()));
            }
        }
        return out;
    }

    /** Extracts state from a full locking script. Returns {@code null} if absent. */
    public static Map<String, Object> extractFromScript(RunarArtifact artifact, String scriptHex) {
        if (!artifact.isStateful()) return null;
        int opReturnPos = ScriptUtils.findLastOpReturn(scriptHex);
        if (opReturnPos < 0) return null;
        String stateHex = scriptHex.substring(opReturnPos + 2);
        return deserialize(artifact.stateFields(), stateHex);
    }

    // ------------------------------------------------------------------
    // Encoding — matches Go encodeStateValue
    // ------------------------------------------------------------------

    static String encodeStateValue(Object value, String fieldType) {
        return switch (fieldType) {
            case "int", "bigint" -> encodeNum2Bin(toBigInteger(value), 8);
            case "bool" -> Boolean.TRUE.equals(value) ? "01" : "00";
            case "PubKey", "Addr", "Ripemd160", "Sha256", "Point" -> String.valueOf(value);
            default -> {
                String hex = String.valueOf(value);
                if (hex.isEmpty()) yield "00";
                yield ScriptUtils.encodePushData(hex);
            }
        };
    }

    /** Encodes a BigInteger as {@code width}-byte little-endian sign-magnitude (OP_NUM2BIN). */
    static String encodeNum2Bin(BigInteger n, int width) {
        boolean negative = n.signum() < 0;
        BigInteger abs = n.abs();
        byte[] buf = new byte[width];
        byte[] bytes = abs.toByteArray(); // big-endian, possibly with sign byte
        // Copy bytes LE into buf, skipping leading sign byte if present.
        int copyLen = Math.min(bytes.length, width);
        for (int i = 0; i < copyLen; i++) {
            buf[i] = bytes[bytes.length - 1 - i];
        }
        if (negative) {
            buf[width - 1] |= (byte) 0x80;
        }
        return ScriptUtils.bytesToHex(buf);
    }

    // ------------------------------------------------------------------
    // Decoding
    // ------------------------------------------------------------------

    static Object decodeStateValue(String hex, int[] offset, String fieldType) {
        return switch (fieldType) {
            case "bool" -> {
                boolean b = !"00".equals(hex.substring(offset[0], offset[0] + 2));
                offset[0] += 2;
                yield b;
            }
            case "int", "bigint" -> {
                int hexWidth = 8 * 2;
                BigInteger v = decodeNum2Bin(hex.substring(offset[0], offset[0] + hexWidth));
                offset[0] += hexWidth;
                yield v;
            }
            case "PubKey" -> {
                String s = hex.substring(offset[0], offset[0] + 66);
                offset[0] += 66;
                yield s;
            }
            case "Addr", "Ripemd160" -> {
                String s = hex.substring(offset[0], offset[0] + 40);
                offset[0] += 40;
                yield s;
            }
            case "Sha256" -> {
                String s = hex.substring(offset[0], offset[0] + 64);
                offset[0] += 64;
                yield s;
            }
            case "Point" -> {
                String s = hex.substring(offset[0], offset[0] + 128);
                offset[0] += 128;
                yield s;
            }
            default -> {
                ScriptUtils.DecodedPush dp = ScriptUtils.decodePushData(hex, offset[0]);
                offset[0] += dp.hexCharsConsumed();
                yield dp.dataHex();
            }
        };
    }

    static BigInteger decodeNum2Bin(String hex) {
        byte[] bytes = ScriptUtils.hexToBytes(hex);
        if (bytes.length == 0) return BigInteger.ZERO;
        boolean negative = (bytes[bytes.length - 1] & 0x80) != 0;
        bytes[bytes.length - 1] &= 0x7f;
        BigInteger result = BigInteger.ZERO;
        for (int i = bytes.length - 1; i >= 0; i--) {
            result = result.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xff));
        }
        return negative ? result.negate() : result;
    }

    // ------------------------------------------------------------------
    // FixedArray helpers (parity with Go parseFixedArrayDims etc.)
    // ------------------------------------------------------------------

    static List<Integer> parseFixedArrayDims(String t) {
        List<Integer> dims = new ArrayList<>();
        String current = t.trim();
        while (current.startsWith("FixedArray<")) {
            String inner = current.substring("FixedArray<".length(), current.length() - 1);
            int splitAt = -1, depth = 0;
            for (int i = inner.length() - 1; i >= 0; i--) {
                char ch = inner.charAt(i);
                if (ch == '>') depth++;
                else if (ch == '<') depth--;
                else if (ch == ',' && depth == 0) { splitAt = i; break; }
            }
            if (splitAt < 0) return dims;
            String elemType = inner.substring(0, splitAt).trim();
            String lenStr = inner.substring(splitAt + 1).trim();
            int n;
            try { n = Integer.parseInt(lenStr); } catch (NumberFormatException e) { return dims; }
            if (n <= 0) return dims;
            dims.add(n);
            current = elemType;
        }
        return dims;
    }

    static String unwrapFixedArrayLeaf(String t) {
        String current = t.trim();
        while (current.startsWith("FixedArray<")) {
            String inner = current.substring("FixedArray<".length(), current.length() - 1);
            int splitAt = -1, depth = 0;
            for (int i = inner.length() - 1; i >= 0; i--) {
                char ch = inner.charAt(i);
                if (ch == '>') depth++;
                else if (ch == '<') depth--;
                else if (ch == ',' && depth == 0) { splitAt = i; break; }
            }
            if (splitAt < 0) return current;
            current = inner.substring(0, splitAt).trim();
        }
        return current;
    }

    @SuppressWarnings("unchecked")
    static List<Object> flattenNestedValue(Object value, List<Integer> dims) {
        if (dims.isEmpty()) {
            List<Object> out = new ArrayList<>();
            out.add(value);
            return out;
        }
        if (!(value instanceof List)) {
            int total = 1;
            for (int d : dims) total *= d;
            List<Object> out = new ArrayList<>(total);
            for (int i = 0; i < total; i++) out.add(null);
            return out;
        }
        List<Integer> rest = dims.subList(1, dims.size());
        List<Object> out = new ArrayList<>();
        for (Object v : (List<Object>) value) {
            out.addAll(flattenNestedValue(v, rest));
        }
        return out;
    }

    static Object regroupNestedValue(List<Object> flat, List<Integer> dims) {
        if (dims.isEmpty()) return flat.isEmpty() ? null : flat.get(0);
        return regroupInner(flat, dims, 0).value;
    }

    private record ConsumedValue(Object value, int consumed) {}

    private static ConsumedValue regroupInner(List<Object> flat, List<Integer> dims, int offset) {
        int outerLen = dims.get(0);
        List<Integer> rest = dims.subList(1, dims.size());
        List<Object> out = new ArrayList<>(outerLen);
        int consumed = 0;
        if (rest.isEmpty()) {
            for (int i = 0; i < outerLen; i++) {
                out.add(offset + i < flat.size() ? flat.get(offset + i) : null);
            }
            consumed = outerLen;
        } else {
            for (int i = 0; i < outerLen; i++) {
                ConsumedValue sub = regroupInner(flat, rest, offset + consumed);
                out.add(sub.value);
                consumed += sub.consumed;
            }
        }
        return new ConsumedValue(out, consumed);
    }

    // ------------------------------------------------------------------
    // Value coercion
    // ------------------------------------------------------------------

    static BigInteger toBigInteger(Object value) {
        if (value == null) return BigInteger.ZERO;
        if (value instanceof BigInteger b) return b;
        if (value instanceof Long l) return BigInteger.valueOf(l);
        if (value instanceof Integer i) return BigInteger.valueOf(i);
        if (value instanceof String s) {
            String t = s.endsWith("n") ? s.substring(0, s.length() - 1) : s;
            return new BigInteger(t);
        }
        throw new IllegalArgumentException("toBigInteger: unsupported " + value.getClass());
    }
}
