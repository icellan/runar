package runar.lang.sdk;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Signed-broadcast wire protocol for overlay apps. Byte-compatible with the
 * TypeScript reference implementation in {@code packages/runar-sdk/src/envelope.ts}.
 *
 * <p>Three primitives:
 * <ul>
 *   <li>{@link #canonicalJson(Object)} — RFC 8785 / JCS serializer (sorted
 *       keys, no whitespace, ES-style number formatting).
 *   <li>{@link #sign(SignEnvelopeOpts)} — bind data + nonce + expiresAt into
 *       a canonical-JSON payload, sha256 it, sign the digest via a caller-
 *       supplied {@link SignFn}.
 *   <li>{@link #verify(VerifyEnvelopeOpts)} — six-reason rejection ladder.
 * </ul>
 */
public final class Envelope {

    private Envelope() {}

    // -------------------------------------------------------------------
    // canonicalJson
    // -------------------------------------------------------------------

    /** Serialize {@code value} to RFC 8785 / JCS canonical JSON. */
    public static String canonicalJson(Object value) {
        StringBuilder sb = new StringBuilder();
        canonicalAppend(sb, value);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void canonicalAppend(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
            return;
        }
        if (value instanceof Boolean) {
            out.append(((Boolean) value) ? "true" : "false");
            return;
        }
        if (value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte) {
            out.append(value.toString());
            return;
        }
        if (value instanceof BigInteger) {
            out.append(value.toString());
            return;
        }
        if (value instanceof Float || value instanceof Double) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("canonical JSON: non-finite number");
            }
            // Java's Double.toString emits "1.0E21" / "1.0E-300" for the
            // scientific cases — that diverges from ECMA-262 §6.1.6.1.13
            // Number::toString ("1e+21" / "1e-300"), so the wire output
            // would not match the TS reference (audit D5). Run the spec
            // algorithm directly.
            out.append(formatEcma262Double(d));
            return;
        }
        if (value instanceof String) {
            appendJsonString(out, (String) value);
            return;
        }
        if (value instanceof List) {
            List<?> list = (List<?>) value;
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) out.append(',');
                canonicalAppend(out, list.get(i));
            }
            out.append(']');
            return;
        }
        if (value instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) value;
            // Sort keys by UTF-16 code-unit order (Java strings ARE UTF-16,
            // so the default String compareTo is exactly the right thing).
            List<String> keys = new ArrayList<>(map.keySet());
            Collections.sort(keys);
            out.append('{');
            boolean first = true;
            for (String k : keys) {
                Object v = map.get(k);
                if (!first) out.append(',');
                first = false;
                appendJsonString(out, k);
                out.append(':');
                canonicalAppend(out, v);
            }
            out.append('}');
            return;
        }
        throw new IllegalArgumentException("canonical JSON: unsupported type " + value.getClass().getName());
    }

    private static void appendJsonString(StringBuilder out, String s) {
        out.append('"');
        // Java strings are UTF-16, so c is a code unit. We must reject any
        // lone surrogate (high without low partner, or low without high
        // partner) before emission — RFC 8785 §3.2.2.2 / audit D6.
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
                    throw new IllegalArgumentException(String.format(
                        "canonical JSON: lone high surrogate U+%04X in string", (int) c));
                }
                // Valid pair: emit both code units verbatim and skip the
                // low half on the next iteration.
                out.append(c);
                out.append(s.charAt(i + 1));
                i++;
                continue;
            }
            if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException(String.format(
                    "canonical JSON: lone low surrogate U+%04X in string", (int) c));
            }
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
    }

    /**
     * Format a finite double per ECMA-262 §6.1.6.1.13 Number::toString. Output
     * is byte-identical to JS {@code JSON.stringify(x)} / {@code String(x)}
     * for any finite {@code x}.
     *
     * <p>ECMA-262 requires the SHORTEST decimal string that round-trips to
     * {@code x} (closest value, ties-to-even). We cannot lean on
     * {@code Double.toString} for the digits: its output is only guaranteed
     * shortest on JDK 19+ (JDK-4511638 / Ryū). On JDK 17 it can emit a
     * longer form — e.g. {@code Double.toString(1e23)} is
     * {@code "9.999999999999999E22"} where ECMAScript yields {@code "1e+23"}
     * — which would make the signed wire bytes diverge from the other six
     * SDK tiers (cross-tier canonicalJson must be byte-identical). So derive
     * the shortest significant-digit string directly: round the exact value
     * of {@code x} to k significant digits (k = 1..17, half-even) and take
     * the smallest k whose rounding still parses back to {@code x}.
     */
    private static String formatEcma262Double(double x) {
        if (x == 0.0) {
            return "0";
        }
        if (x < 0.0) {
            return "-" + formatEcma262Double(-x);
        }
        BigDecimal exact = new BigDecimal(x);
        BigDecimal rounded = exact;
        for (int precision = 1; precision <= 17; precision++) {
            BigDecimal cand = exact.round(new MathContext(precision, RoundingMode.HALF_EVEN));
            if (cand.doubleValue() == x) {
                rounded = cand;
                break;
            }
        }
        // Strip trailing zeros so `digits` carries only significant digits and
        // `k` (the count of integer-part digits in plain notation, i.e.
        // ECMAScript's `n`) is computed cleanly.
        rounded = rounded.stripTrailingZeros();
        String digits = rounded.unscaledValue().toString(); // x > 0: no sign
        int k = digits.length() - rounded.scale();
        int sLen = digits.length();
        if (k >= sLen && k <= 21) {
            StringBuilder b = new StringBuilder(digits);
            for (int i = 0; i < k - sLen; i++) b.append('0');
            return b.toString();
        }
        if (k > 0 && k <= 21) {
            return digits.substring(0, k) + "." + digits.substring(k);
        }
        if (k > -6 && k <= 0) {
            StringBuilder b = new StringBuilder("0.");
            for (int i = 0; i < -k; i++) b.append('0');
            b.append(digits);
            return b.toString();
        }
        int exp = k - 1;
        String expStr = (exp < 0) ? ("e-" + (-exp)) : ("e+" + exp);
        if (sLen == 1) {
            return digits + expStr;
        }
        return digits.charAt(0) + "." + digits.substring(1) + expStr;
    }

    // -------------------------------------------------------------------
    // SignedEnvelope
    // -------------------------------------------------------------------

    /** Wire format for a signed broadcast payload. */
    public static final class SignedEnvelope {
        public final String payload;
        public final String sig;
        public final String pubkey;
        public final long nonce;
        public final long expiresAt;

        public SignedEnvelope(String payload, String sig, String pubkey, long nonce, long expiresAt) {
            this.payload = payload;
            this.sig = sig;
            this.pubkey = pubkey;
            this.nonce = nonce;
            this.expiresAt = expiresAt;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("payload", payload);
            m.put("sig", sig);
            m.put("pubkey", pubkey);
            m.put("nonce", nonce);
            m.put("expiresAt", expiresAt);
            return m;
        }

        public static SignedEnvelope fromMap(Map<String, Object> m) {
            return new SignedEnvelope(
                (String) m.get("payload"),
                (String) m.get("sig"),
                (String) m.get("pubkey"),
                ((Number) m.get("nonce")).longValue(),
                ((Number) m.get("expiresAt")).longValue()
            );
        }
    }

    /** Closure signing a 32-byte digest, returning DER signature bytes. */
    @FunctionalInterface
    public interface SignFn extends Function<byte[], byte[]> {}

    public static final class SignEnvelopeOpts {
        public Map<String, Object> data;
        public SignFn signer;
        /** 66-char hex compressed secp256k1 pubkey of the signer. */
        public String pubkey;
        /** Defaults to 30_000. */
        public long ttlMs = 30_000;
        /** Override Now() for deterministic tests; 0 = wall clock. */
        public long nowMs = 0;
    }

    public static SignedEnvelope sign(SignEnvelopeOpts opts) {
        long nonce = opts.nowMs != 0 ? opts.nowMs : System.currentTimeMillis();
        long expiresAt = nonce + opts.ttlMs;
        Map<String, Object> merged = new LinkedHashMap<>(opts.data == null ? Collections.emptyMap() : opts.data);
        merged.put("nonce", nonce);
        merged.put("expiresAt", expiresAt);
        String payload = canonicalJson(merged);
        byte[] digest = sha256(payload.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = opts.signer.apply(digest);
        return new SignedEnvelope(payload, toHex(sigBytes), opts.pubkey, nonce, expiresAt);
    }

    // -------------------------------------------------------------------
    // verify
    // -------------------------------------------------------------------

    public enum VerifyEnvelopeReason {
        MISSING_FIELDS("missing-fields"),
        EXPIRED("expired"),
        BAD_JSON("bad-json"),
        ENVELOPE_MISMATCH("envelope-mismatch"),
        BAD_SIG("bad-sig"),
        PUBKEY_NOT_ALLOWED("pubkey-not-allowed"),
        /**
         * Mirrors the TS 'too-large' reason. Returned BEFORE any JSON parse /
         * ECDSA verify work when an envelope string field exceeds its
         * InputLimits cap (DoS-bound). BUG-008 follow-up.
         */
        TOO_LARGE("too-large");

        public final String wire;
        VerifyEnvelopeReason(String wire) { this.wire = wire; }
    }

    /**
     * Envelope DoS-bound caps. Mirror {@code InputLimits.MAX_IR_BYTES} and
     * {@code InputLimits.MAX_STRING_BYTES} from the TS schema package.
     * BUG-008 follow-up.
     */
    public static final int MAX_ENVELOPE_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MiB
    public static final int MAX_ENVELOPE_FIELD_BYTES = 4 * 1024 * 1024;    // 4 MiB

    /**
     * Maximum payload nesting {@link #verify} will parse: the number of containers
     * enclosing a value, 1-based, outermost = 1. 100 is accepted, 101 is rejected.
     * R-260.
     *
     * Without an explicit bound the limit was whatever each tier's stock JSON library
     * imposed, and those differ. Measured on ONE envelope, payload
     * {"deep":<N-deep array>,...}: ruby flipped to bad-json at total depth 101
     * (JSON.parse default max_nesting: 100) and rust at 128 (serde_json
     * RECURSION_LIMIT); ts, go, python and zig accepted every depth probed (zig's
     * iterative scanner took 100001 without complaint); and java threw
     * StackOverflowError straight OUT of verify -- its hand-written parser is
     * recursive with no cap and verify catches Exception, not Error -- at ~5000 deep
     * on a default JVM stack and ~1000 deep under -Xss512k, i.e. a contract escape on
     * unauthenticated input whose threshold was a JVM launch flag rather than a
     * protocol property.
     *
     * 100 is Ruby's native JSON.parse default EXACTLY and sits 27 below rust's 127,
     * so no tier has to hand-roll or reconfigure its parser to stay inside it. It is
     * also far above what the wire needs: the deepest of the 157 checked-in
     * conformance artifacts is depth 15 and conformance/sdk-envelope/fixtures.json
     * tops out at 6. The number is deliberately the SAME as canonicalJson's emit-side
     * bound: if parse were the smaller of the two, a tier could emit a legal,
     * correctly-signed envelope that another tier is physically unable to parse.
     *
     * The guard runs on the payload TEXT, immediately before the stock parser, and is
     * a flat non-recursive bracket scan so the guard itself cannot overflow.
     */
    public static final int MAX_ENVELOPE_PAYLOAD_DEPTH = 100;

    /**
     * Does the payload text nest deeper than MAX_ENVELOPE_PAYLOAD_DEPTH?
     *
     * Counts the maximum number of simultaneously-open {/[ containers, skipping
     * anything inside a JSON string (so a value of "[[[[..." is not nesting). The
     * scan is FLAT -- no recursion -- which is the point: a guard that recursed
     * would overflow on exactly the input it exists to reject. It bails out the
     * instant the bound is passed, so a 200 KB bracket bomb costs a few hundred
     * bytes of scanning.
     *
     * This does not validate JSON; malformed input still falls through to the real
     * parser and its own bad-json rejection.
     */
    static boolean payloadExceedsMaxDepth(String payload) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < payload.length(); i++) {
            char c = payload.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{' || c == '[') {
                depth++;
                if (depth > MAX_ENVELOPE_PAYLOAD_DEPTH) {
                    return true;
                }
            } else if ((c == '}' || c == ']') && depth > 0) {
                depth--;
            }
        }
        return false;
    }

    public static final class VerifyEnvelopeOpts {
        public SignedEnvelope envelope;
        /** Optional pubkey allowlist (66-char hex). */
        public List<String> expectedKeys;
        /**
         * Allowed wall-clock skew in ms when checking expiresAt. Defaults to
         * 5_000; an explicit 0 means zero tolerance and IS honoured.
         */
        public long clockSkewMs = 5_000;
        /**
         * Overrides the wall clock used to check expiry. NULL means the caller
         * supplied nothing and {@code System.currentTimeMillis()} is used; a
         * non-null value is used AS GIVEN, so an explicit 0 means the Unix
         * epoch — under which nothing has expired yet — rather than "fall back
         * to the wall clock".
         *
         * <p>R-261: this was a {@code long} defaulting to 0 and read as
         * {@code nowMs != 0 ? nowMs : System.currentTimeMillis()}, which made
         * an explicit 0 indistinguishable from "not supplied". Python, Ruby,
         * Rust and Zig all treat an explicit 0 as the epoch and returned
         * ok:true on an envelope this tier called expired.
         */
        public Long nowMs = null;
    }

    public static final class VerifyEnvelopeResult {
        public final boolean ok;
        public final VerifyEnvelopeReason reason;
        public final Map<String, Object> data;

        public VerifyEnvelopeResult(boolean ok, VerifyEnvelopeReason reason, Map<String, Object> data) {
            this.ok = ok;
            this.reason = reason;
            this.data = data;
        }
    }

    /**
     * Unpaired-surrogate detection on an envelope payload (R-115 / CL-BUG-066).
     *
     * <p>{@code verify} hashes the payload string RAW — it never routes it
     * through {@link #canonicalJson} — so canonicalJson's lone-surrogate
     * rejection (audit D6, fixture vector v22) never sees the envelope path,
     * and each tier fell back on whatever its JSON parser happened to do.
     *
     * <p>Two shapes count as unpaired: a {@code \\uD800}–{@code \\uDBFF}
     * escape not immediately followed by a low-surrogate escape (or a lone low
     * one), and a raw unpaired surrogate {@code char} in the text.
     */
    static boolean payloadHasLoneSurrogate(String text) {
        if (text == null) {
            return false;
        }
        // Raw code units first — a Java String can hold an unpaired surrogate.
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(i + 1))) {
                    return true;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return true;
            }
        }

        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) != '\\') {
                continue;
            }
            int run = 0;
            while (i + run < text.length() && text.charAt(i + run) == '\\') {
                run++;
            }
            int esc = i + run - 1;
            i = esc;
            if (run % 2 == 0) {
                continue;
            }
            int code = escapedCodeUnitAt(text, esc);
            if (code < 0) {
                continue;
            }
            if (code >= 0xD800 && code <= 0xDBFF) {
                int low = escapedCodeUnitAt(text, esc + 6);
                if (low < 0xDC00 || low > 0xDFFF) {
                    return true;
                }
                i = esc + 11;
            } else if (code >= 0xDC00 && code <= 0xDFFF) {
                return true;
            } else {
                i = esc + 5;
            }
        }
        return false;
    }

    /** The code unit of a {@code \\uXXXX} escape starting at {@code i}, or -1. */
    private static int escapedCodeUnitAt(String text, int i) {
        if (i < 0 || i + 5 >= text.length() || text.charAt(i) != '\\' || text.charAt(i + 1) != 'u') {
            return -1;
        }
        int code = 0;
        for (int k = 0; k < 4; k++) {
            int v = Character.digit(text.charAt(i + 2 + k), 16);
            if (v < 0) {
                return -1;
            }
            code = code * 16 + v;
        }
        return code;
    }

    public static VerifyEnvelopeResult verify(VerifyEnvelopeOpts opts) {
        SignedEnvelope env = opts.envelope;

        // 0. DoS-bound size guard. Reject envelopes whose string fields exceed
        //    their InputLimits cap BEFORE running JSON parse, hashing, or
        //    ECDSA verify -- those operations are linear in input size and a
        //    pathological 100 MB payload would otherwise pin the worker.
        //    Mirrors the TS 'too-large' rejection at sdk/envelope.ts:104.
        //    BUG-008 follow-up.
        if (env != null) {
            if (env.payload != null) {
                int payloadBytes = env.payload.getBytes(StandardCharsets.UTF_8).length;
                if (payloadBytes > MAX_ENVELOPE_PAYLOAD_BYTES) {
                    return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.TOO_LARGE, null);
                }
            }
            if (env.sig != null && env.sig.length() > MAX_ENVELOPE_FIELD_BYTES) {
                return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.TOO_LARGE, null);
            }
            if (env.pubkey != null && env.pubkey.length() > MAX_ENVELOPE_FIELD_BYTES) {
                return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.TOO_LARGE, null);
            }
        }

        // 1. Field presence + types.
        if (env == null || env.payload == null || env.payload.isEmpty()
                || env.sig == null || env.sig.isEmpty()
                || env.pubkey == null || env.pubkey.isEmpty()
                || env.nonce == 0 || env.expiresAt == 0) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.MISSING_FIELDS, null);
        }

        long now = opts.nowMs != null ? opts.nowMs : System.currentTimeMillis();

        // 2. Expiry.
        if (env.expiresAt < now - opts.clockSkewMs) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.EXPIRED, null);
        }

        // 3. Parse payload.
        //
        // R-115: an unpaired surrogate makes the payload ill-formed Unicode,
        // and the seven tiers' JSON parsers disagree about it — ts/go/python/
        // java accepted it and fell through to bad-sig, rust/ruby/zig rejected
        // it here. Decided on the payload TEXT so every tier answers the same.
        if (payloadHasLoneSurrogate(env.payload)) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.BAD_JSON, null);
        }
        // R-260: bound nesting on the TEXT, before Json.parse. This tier needs
        // it most: Json's readValue/readObject/readArray are mutually recursive
        // with no cap, and the catch below is on Exception — a StackOverflowError
        // is an Error, so before this guard a ~10 KB deep payload escaped verify
        // entirely instead of returning a VerifyEnvelopeResult. Same bound and
        // same reason in all seven tiers.
        if (payloadExceedsMaxDepth(env.payload)) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.BAD_JSON, null);
        }
        Map<String, Object> parsed;
        try {
            Object raw = Json.parse(env.payload);
            if (!(raw instanceof Map)) {
                return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.BAD_JSON, null);
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) raw;
            parsed = m;
        } catch (Exception e) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.BAD_JSON, null);
        }

        // 4. Inner nonce / expiresAt must match outer fields.
        Long innerNonce = readLong(parsed.get("nonce"));
        Long innerExpiresAt = readLong(parsed.get("expiresAt"));
        if (innerNonce == null || innerExpiresAt == null
                || innerNonce != env.nonce || innerExpiresAt != env.expiresAt) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.ENVELOPE_MISMATCH, parsed);
        }

        // 5. ECDSA verify (raw, no re-hashing).
        try {
            byte[] sigBytes = fromHex(env.sig);
            byte[] pkBytes = fromHex(env.pubkey);
            ECPoint q = LocalSigner.DOMAIN.getCurve().decodePoint(pkBytes);
            ECPublicKeyParameters params = new ECPublicKeyParameters(q, LocalSigner.DOMAIN);
            ECDSASigner verifier = new ECDSASigner();
            verifier.init(false, params);
            ASN1Sequence seq = ASN1Sequence.getInstance(sigBytes);
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            byte[] digest = sha256(env.payload.getBytes(StandardCharsets.UTF_8));
            if (!verifier.verifySignature(digest, r, s)) {
                return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.BAD_SIG, parsed);
            }
        } catch (Exception e) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.BAD_SIG, parsed);
        }

        // 6. Allowlist.
        if (opts.expectedKeys != null && !opts.expectedKeys.contains(env.pubkey)) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.PUBKEY_NOT_ALLOWED, parsed);
        }

        return new VerifyEnvelopeResult(true, null, parsed);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    private static Long readLong(Object o) {
        if (o instanceof Long) return (Long) o;
        if (o instanceof Integer) return ((Integer) o).longValue();
        if (o instanceof Number) return ((Number) o).longValue();
        return null;
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private static byte[] fromHex(String hex) {
        int len = hex.length();
        if ((len & 1) != 0) throw new IllegalArgumentException("hex length must be even");
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("invalid hex");
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
