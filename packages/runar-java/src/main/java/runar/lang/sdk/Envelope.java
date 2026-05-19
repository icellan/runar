package runar.lang.sdk;

import java.math.BigInteger;
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
     * for any finite {@code x}. {@code Double.toString} alone diverges
     * ("1.0E21" vs "1e+21" — audit D5), so we re-derive the digit string and
     * decimal exponent from the surface form and re-emit per the spec rules.
     */
    private static String formatEcma262Double(double x) {
        if (x == 0.0) {
            return "0";
        }
        if (x < 0.0) {
            return "-" + formatEcma262Double(-x);
        }
        String s = Double.toString(x);
        // Split into mantissa and explicit exponent.
        int ePos = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 'e' || c == 'E') {
                ePos = i;
                break;
            }
        }
        String mantissa;
        int expPart;
        if (ePos >= 0) {
            mantissa = s.substring(0, ePos);
            expPart = Integer.parseInt(s.substring(ePos + 1));
        } else {
            mantissa = s;
            expPart = 0;
        }
        int dot = mantissa.indexOf('.');
        String intPart;
        String fracPart;
        if (dot >= 0) {
            intPart = mantissa.substring(0, dot);
            fracPart = mantissa.substring(dot + 1);
        } else {
            intPart = mantissa;
            fracPart = "";
        }
        String rawDigits = intPart + fracPart;
        int leadingZeros = 0;
        while (leadingZeros < rawDigits.length() && rawDigits.charAt(leadingZeros) == '0') {
            leadingZeros++;
        }
        String trimmed = rawDigits.substring(leadingZeros);
        int end = trimmed.length();
        while (end > 0 && trimmed.charAt(end - 1) == '0') {
            end--;
        }
        String digits = trimmed.substring(0, end);
        if (digits.isEmpty()) {
            return "0";
        }
        int k = intPart.length() - leadingZeros + expPart;
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
        PUBKEY_NOT_ALLOWED("pubkey-not-allowed");

        public final String wire;
        VerifyEnvelopeReason(String wire) { this.wire = wire; }
    }

    public static final class VerifyEnvelopeOpts {
        public SignedEnvelope envelope;
        /** Optional pubkey allowlist (66-char hex). */
        public List<String> expectedKeys;
        /** Defaults to 5_000. */
        public long clockSkewMs = 5_000;
        /** Override Now() for deterministic tests; 0 = wall clock. */
        public long nowMs = 0;
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

    public static VerifyEnvelopeResult verify(VerifyEnvelopeOpts opts) {
        SignedEnvelope env = opts.envelope;

        // 1. Field presence + types.
        if (env == null || env.payload == null || env.payload.isEmpty()
                || env.sig == null || env.sig.isEmpty()
                || env.pubkey == null || env.pubkey.isEmpty()
                || env.nonce == 0 || env.expiresAt == 0) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.MISSING_FIELDS, null);
        }

        long now = opts.nowMs != 0 ? opts.nowMs : System.currentTimeMillis();

        // 2. Expiry.
        if (env.expiresAt < now - opts.clockSkewMs) {
            return new VerifyEnvelopeResult(false, VerifyEnvelopeReason.EXPIRED, null);
        }

        // 3. Parse payload.
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
