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
                    sb.append(encodeStateValue(elem, leafType, synth));
                }
            } else {
                sb.append(encodeStateValue(values.get(f.name()), f.type(), f.name()));
            }
        }
        return sb.toString();
    }

    /**
     * Deserialises state from the raw hex bytes between the OP_RETURN
     * separator and the end of the script.
     *
     * <p>FAILS CLOSED (C2, porting TypeScript's C28). The blob is read back out
     * of a locking script any third party can construct, so it is untrusted
     * input, and the caller then builds and SIGNS a continuation output
     * committing to the restored state. A state section that does not describe
     * EXACTLY {@code fields} is rejected:
     *
     * <ul>
     *   <li>truncation — a field running past the end of the blob throws
     *       {@link IllegalArgumentException}. Every arm used to be a bare
     *       {@code hex.substring(offset, offset + N)} that threw a raw
     *       {@link StringIndexOutOfBoundsException} instead: a JDK bounds error
     *       escaping the SDK on attacker-controlled input, not a refusal.</li>
     *   <li>overlong tails — bytes left over after the last declared field
     *       throw instead of being silently dropped.</li>
     * </ul>
     *
     * <p>Restoring wrong-but-plausible state from a corrupted continuation is
     * worse than not restoring it at all.
     *
     * @throws IllegalArgumentException if the blob does not match {@code fields} exactly
     */
    public static Map<String, Object> deserialize(List<StateField> fields, String scriptHex) {
        if (scriptHex.length() % 2 != 0) {
            throw new IllegalArgumentException(
                "deserializeState: state blob is " + scriptHex.length()
                    + " hex chars — not a whole number of bytes");
        }
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
                    flat.add(decodeStateValue(scriptHex, offset, leafType, f.name() + "[" + i + "]"));
                }
                out.put(f.name(), regroupNestedValue(flat, dims));
            } else {
                out.put(f.name(), decodeStateValue(scriptHex, offset, f.type(), f.name()));
            }
        }
        if (offset[0] != scriptHex.length()) {
            throw new IllegalArgumentException(String.format(
                "deserializeState: %d unexpected trailing byte(s) after the last state field "
                    + "(consumed %d of %d bytes) — the state section does not match the "
                    + "artifact's stateFields",
                (scriptHex.length() - offset[0]) / 2, offset[0] / 2, scriptHex.length() / 2));
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

    static String encodeStateValue(Object value, String fieldType, String label) {
        return switch (fieldType) {
            case "int", "bigint" -> encodeNum2Bin(toBigInteger(value), 8, label);
            // 1 raw byte. The canonical Rúnar primitive name is `boolean` — that is
            // what every compiler writes into stateFields[].type, alongside
            // encoding "bool1" / byteLength 1 — and `bool` is an accepted alias.
            // Matching only on "bool" meant a REAL boolean state field fell through
            // to the push-data default below and was framed as the ASCII text
            // 02 74727565: 3 bytes longer than the continuation the script's own
            // reader rebuilds, so hash256(outputs) never matched and the first
            // spend was impossible.
            case "bool", "boolean" -> Boolean.TRUE.equals(value) ? "01" : "00";
            // Fixed-size byte types: raw hex, no framing needed. P256Point (64)
            // and P384Point (96) belong here because runar-lang's cast
            // constructors hard-assert those widths and all seven compilers emit
            // them as fixed raw slices; framing them instead deploys a state
            // section 1-2 bytes long and the first spend fails.
            //
            // A MISSING value is refused rather than formatted.
            // String.valueOf(null) is "null", which is not hex — and the other
            // six SDKs each invented a DIFFERENT non-hex placeholder for the
            // same mistake (Go "<nil>", TS "undefined", Python/Ruby ""), a
            // silent byte divergence on a path whose bytes are committed on
            // chain. Refusing is the only answer that is the same in every tier.
            case "PubKey", "Addr", "Ripemd160", "Sha256", "Point", "P256Point", "P384Point" -> {
                if (value == null) {
                    throw new IllegalArgumentException(String.format(
                        "serializeState: state field \"%s\" (%s) has no value. Writing a "
                            + "placeholder would deploy a state section the contract's own "
                            + "on-chain reader cannot parse, leaving the output unspendable",
                        label, fieldType));
                }
                yield String.valueOf(value);
            }
            default -> {
                String hex = String.valueOf(value);
                if (hex.isEmpty()) yield "00";
                yield ScriptUtils.encodePushDataState(hex);
            }
        };
    }

    /**
     * Encodes a BigInteger as {@code width}-byte little-endian sign-magnitude (OP_NUM2BIN).
     *
     * <p>FAILS CLOSED on an out-of-range magnitude. {@code width} bytes of sign-magnitude
     * hold {@code 8*width - 1} magnitude bits — the top bit of the last byte is the sign.
     * The copy below writes the low {@code width} bytes and drops everything above, then
     * ORs the sign bit in on top of whatever landed there, so an oversized value used to
     * serialise to a plausible but WRONG word:
     *
     * <pre>
     * 2^63      -&gt; 0000000000000080   reads back as 0   (negative zero)
     * 2^63 + 5  -&gt; 0500000000000080   reads back as -5  (sign flip)
     * 2^64      -&gt; 0000000000000000   reads back as 0
     * </pre>
     *
     * <p>The deploy then succeeded and the UTXO was unspendable: the covenant rebuilds the
     * continuation with the compiler's own OP_NUM2BIN {@code width}, which cannot produce
     * those bytes from that number, so hash256(outputs) never matches. Throwing here is the
     * only place a runtime-computed state value can be stopped —
     * {@code ±(2^(8*width-1) - 1)} remains representable and is unaffected.
     *
     * @throws IllegalArgumentException if the magnitude does not fit the state word
     */
    static String encodeNum2Bin(BigInteger n, int width, String label) {
        BigInteger limit = BigInteger.ONE.shiftLeft(8 * width - 1);
        if (n.abs().compareTo(limit) >= 0) {
            throw new IllegalArgumentException(
                "serializeState: bigint state field \"" + label + "\" = " + n
                    + " does not fit the fixed " + width
                    + "-byte sign-magnitude state word (magnitude must be < 2^"
                    + (8 * width - 1) + "). Serializing it would write a different number into"
                    + " the state section than the contract's on-chain OP_NUM2BIN " + width
                    + " rebuilds, leaving the output unspendable.");
        }

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

    /**
     * Fixed on-wire width of a state field type in bytes, or {@code null} if the
     * type is variable-width. The single table {@code encodeStateValue}'s raw
     * branch and {@code decodeStateValue}'s bounds check both read, so the
     * writer and the reader cannot drift.
     */
    static Integer stateFieldByteWidth(String fieldType) {
        return switch (fieldType) {
            case "bool", "boolean" -> 1;
            case "int", "bigint" -> 8;
            case "PubKey" -> 33;
            case "Addr", "Ripemd160" -> 20;
            case "Sha256" -> 32;
            case "Point", "P256Point" -> 64;
            case "P384Point" -> 96;
            default -> null;
        };
    }

    static Object decodeStateValue(String hex, int[] offset, String fieldType, String label) {
        Integer width = stateFieldByteWidth(fieldType);
        if (width == null) {
            // Variable-length / unknown types: push-data decoding.
            ScriptUtils.DecodedPush dp = ScriptUtils.decodePushDataState(hex, offset[0]);
            offset[0] += dp.hexCharsConsumed();
            return dp.dataHex();
        }
        int hexWidth = width * 2;
        if (offset[0] + hexWidth > hex.length()) {
            throw new IllegalArgumentException(String.format(
                "deserializeState: truncated state — field \"%s\" (%s) needs %d byte(s) at "
                    + "offset %d but only %d byte(s) remain",
                label, fieldType, width, offset[0] / 2,
                Math.max(0, hex.length() - offset[0]) / 2));
        }
        String data = hex.substring(offset[0], offset[0] + hexWidth);
        offset[0] += hexWidth;
        // Both spellings, matching encodeStateValue — a reader that knows only
        // "bool" walks a real boolean field as push data and desynchronises
        // every field after it.
        if (fieldType.equals("bool") || fieldType.equals("boolean")) return !"00".equals(data);
        // 8 raw bytes LE sign-magnitude (NUM2BIN 8).
        if (fieldType.equals("int") || fieldType.equals("bigint")) return decodeNum2Bin(data);
        // Raw fixed-size byte types.
        return data;
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

    /**
     * Spreads every grouped FixedArray entry of a state record ({@code table}
     * holding a possibly-nested list of length N) over the SYNTHETIC scalar
     * names the leaves are really called ({@code table__0}..{@code table__3},
     * {@code grid__0__0}..). The grouped entries are kept as well, for callers
     * that read them afterwards.
     *
     * <p>This is the ANF-interpreter boundary. Pass {@code 03b-expand-fixed-arrays}
     * runs BEFORE ANF lowering, so the ANF program has no property called
     * {@code table} at all — every {@code load_prop} / {@code update_prop} in
     * the method body names one of the synthetic leaves. Handing the interpreter
     * the grouped map left it evaluating {@code this.table[i]++} against an
     * ABSENT property and falling back to the property's {@code initialValue};
     * because a runtime-index write lowers to a per-leaf select it rewrites
     * EVERY leaf, so a call on a contract restored from chain rewound the whole
     * array to its deploy-time contents.
     *
     * <p>Mirrors {@code flattenFixedArrayState} in packages/runar-sdk/src/contract.ts
     * and packages/runar-go/sdk_contract.go, and
     * {@code _flatten_fixed_array_state} in packages/runar-py/runar/sdk/contract.py,
     * including their two rules: a non-list value is NOT spread over N leaves
     * (nothing sensible to spread), and an explicitly-supplied scalar wins over
     * the grouped list it is also spelled inside.
     */
    public static Map<String, Object> flattenFixedArrayState(
        List<StateField> fields,
        Map<String, Object> state
    ) {
        Map<String, Object> out = new LinkedHashMap<>(state);
        if (fields == null) return out;
        for (StateField f : fields) {
            if (f.fixedArray() == null) continue;
            Object value = state.get(f.name());
            if (!(value instanceof List)) continue;
            List<Object> flat = flattenNestedValue(value, parseFixedArrayDims(f.type()));
            List<String> names = f.fixedArray().syntheticNames();
            for (int i = 0; i < names.size(); i++) {
                String synth = names.get(i);
                if (out.containsKey(synth)) continue;
                if (i < flat.size()) out.put(synth, flat.get(i));
            }
        }
        return out;
    }

    /**
     * Rebuilds each grouped FixedArray entry of a state record from the
     * synthetic scalar leaves the ANF interpreter writes, so the user-facing
     * {@code state()} and the serializer's grouped fallback both see the
     * post-call value rather than the pre-call one. Synthetic entries are left
     * in place; non-FixedArray fields pass through untouched.
     *
     * <p>A field whose leaves are entirely absent from the map is left alone:
     * the method did not touch that array, so there is nothing to reconstruct.
     * A leaf the method did not write falls back to its pre-call value from the
     * grouped entry, so a partial write keeps the untouched slots instead of
     * zeroing them.
     *
     * <p>Mirrors {@code regroupFixedArrayState} / {@code _regroup_fixed_array_state}
     * in the TS, Go and Python SDKs.
     */
    public static Map<String, Object> regroupFixedArrayState(
        List<StateField> fields,
        Map<String, Object> state
    ) {
        Map<String, Object> out = new LinkedHashMap<>(state);
        if (fields == null) return out;
        for (StateField f : fields) {
            if (f.fixedArray() == null) continue;
            List<String> names = f.fixedArray().syntheticNames();
            List<Object> flat = new ArrayList<>(names.size());
            boolean[] written = new boolean[names.size()];
            boolean sawAny = false;
            for (int i = 0; i < names.size(); i++) {
                String synth = names.get(i);
                if (out.containsKey(synth)) {
                    flat.add(out.get(synth));
                    written[i] = true;
                    sawAny = true;
                } else {
                    flat.add(null);
                }
            }
            if (!sawAny) continue;
            List<Integer> dims = parseFixedArrayDims(f.type());
            Object prior = state.get(f.name());
            if (prior instanceof List) {
                List<Object> priorFlat = flattenNestedValue(prior, dims);
                for (int i = 0; i < flat.size(); i++) {
                    if (!written[i] && i < priorFlat.size()) flat.set(i, priorFlat.get(i));
                }
            }
            out.put(f.name(), regroupNestedValue(flat, dims));
        }
        return out;
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
