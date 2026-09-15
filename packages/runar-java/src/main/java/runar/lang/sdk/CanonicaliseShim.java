package runar.lang.sdk;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Java-tier CLI shim for the cross-tier canonicalJson (RFC 8785 / JCS)
 * differential fuzzer ({@code conformance/fuzzer/canonical-json-differential.ts}).
 *
 * <p>Protocol (single-shot, stdin -&gt; stdout), mirrors the Go / Rust / Python /
 * Zig / Ruby shims:
 *
 * <ul>
 *   <li>{@code {"mode":"json","value":<any JSON>}} — parse {@code value} with
 *       {@link Json#parse(String)} (Long / BigInteger / Double, preserving the
 *       int-vs-float distinction the interop test relies on), run
 *       {@link Envelope#canonicalJson(Object)}, print bytes, exit 0.</li>
 *   <li>{@code {"mode":"utf16","key":"<string>","units":[<int>,...]}} — build
 *       {@code {key: <string from UTF-16 code units>}}. Java {@code String} is a
 *       UTF-16 char sequence and can hold a lone surrogate, so the rejection
 *       happens inside {@link Envelope#canonicalJson} (mirrors the interop
 *       test's surrogate check).</li>
 *   <li>{@code {"mode":"deep","depth":<int>,"shape":"array"|"object"}} — build
 *       {@code depth} nested containers around the integer leaf 1, NATIVELY.</li>
 *   <li>{@code {"mode":"bigstring","bytes":<int>,"where":"value"|"key"}} — build
 *       a one-entry map whose value (or key) is {@code bytes} ASCII 'a',
 *       NATIVELY, and respond with the SHA-256 of the canonical bytes rather
 *       than the bytes themselves.</li>
 * </ul>
 *
 * <p>Why {@code deep} / {@code bigstring} describe the value instead of carrying
 * it: a deep or huge value delivered as JSON would have to survive THIS shim's
 * own {@link Json#parse} before reaching canonicalJson, so the transport would
 * be imposing a limit on the very thing under test. Building natively keeps the
 * request ~50 bytes and takes the request parser out of the measurement.
 * Hashing the bigstring response keeps a ~4 MiB canonical output off the pipe
 * while still detecting a single divergent byte — and keeps the batch shim's
 * line-based framing intact.
 *
 * <p>On a typed canonicalJson rejection the shim prints
 * {@code "RUNAR_CANON_ERR:<message>"} to stdout and exits 3; any other failure
 * exits 1.
 *
 * <p>Run via: {@code gradle -q runCanonicalise} (stdin piped in). A batched
 * peer, {@link CanonicaliseBatchShim} ({@code gradle -q runCanonicaliseBatch}),
 * processes a whole corpus in ONE JVM by calling {@link #process(String)} per
 * request line — used by the deterministic Java PR gate.
 */
public final class CanonicaliseShim {

    /** Prefix stdout carries on a typed canonicalJson rejection. Mirrors the
     *  {@code REJECT_PREFIX} the TS differential driver keys on. */
    static final String REJECT_PREFIX = "RUNAR_CANON_ERR:";

    private CanonicaliseShim() {
    }

    public static void main(String[] args) {
        String raw;
        try {
            raw = readAll(System.in);
        } catch (Exception e) {
            System.err.println("read stdin: " + e.getMessage());
            System.exit(1);
            return;
        }

        String out;
        try {
            out = process(raw);
        } catch (RequestError e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }

        System.out.print(out);
        System.out.flush();
        if (out.startsWith(REJECT_PREFIX)) {
            System.exit(3);
        }
    }

    /**
     * Parse one request and return the canonical bytes, or a
     * {@link #REJECT_PREFIX}-tagged message on a typed canonicalJson rejection.
     *
     * <p>Throws {@link RequestError} for a malformed request (bad JSON / unknown
     * mode) — a protocol-level error, kept distinct from a canonicalJson
     * rejection so the single-shot {@link #main} can preserve its exit-code
     * contract (1 for a bad request, 3 for a rejection).
     */
    static String process(String raw) throws RequestError {
        Object input;
        String mode;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> req = (Map<String, Object>) Json.parse(raw);
            mode = String.valueOf(req.get("mode"));
            if ("json".equals(mode)) {
                input = req.get("value");
            } else if ("utf16".equals(mode)) {
                String key = req.get("key") == null ? "" : String.valueOf(req.get("key"));
                @SuppressWarnings("unchecked")
                List<Object> units = (List<Object>) req.get("units");
                Map<String, Object> obj = new LinkedHashMap<>();
                obj.put(key, utf16UnitsToString(units));
                input = obj;
            } else if ("deep".equals(mode)) {
                input = buildDeep(
                    ((Number) req.get("depth")).intValue(),
                    req.get("shape") == null ? "array" : String.valueOf(req.get("shape")));
            } else if ("bigstring".equals(mode)) {
                input = buildBigString(
                    ((Number) req.get("bytes")).intValue(),
                    req.get("where") == null ? "value" : String.valueOf(req.get("where")));
            } else {
                throw new RequestError("unknown mode " + mode);
            }
        } catch (RequestError e) {
            throw e;
        } catch (Exception e) {
            throw new RequestError("parse request: " + e.getMessage());
        }

        String out;
        try {
            out = Envelope.canonicalJson(input);
        } catch (StackOverflowError e) {
            // Native stack exhaustion is not the typed rejection a guard
            // produces; keep it distinguishable so it cannot be scored as
            // agreement with a tier that rejected properly.
            return REJECT_PREFIX + "StackOverflowError (native stack, not a guard)";
        } catch (RuntimeException e) {
            return REJECT_PREFIX + e.getMessage();
        }
        if ("bigstring".equals(mode)) {
            return DIGEST_PREFIX + sha256Hex(out);
        }
        return out;
    }

    /** Prefix stdout carries when the response is a digest rather than the
     *  canonical bytes (bigstring mode). */
    static final String DIGEST_PREFIX = "RUNAR_CANON_SHA256:";

    /** Nest {@code depth} containers around the integer leaf 1, iteratively. */
    private static Object buildDeep(int depth, String shape) {
        Object v = 1L;
        for (int i = 0; i < depth; i++) {
            if ("array".equals(shape)) {
                List<Object> arr = new java.util.ArrayList<>(1);
                arr.add(v);
                v = arr;
            } else {
                Map<String, Object> obj = new LinkedHashMap<>();
                obj.put("k", v);
                v = obj;
            }
        }
        return v;
    }

    /** One-entry map whose value (or key) is {@code n} ASCII 'a'. */
    private static Object buildBigString(int n, String where) {
        char[] chars = new char[n];
        java.util.Arrays.fill(chars, 'a');
        String s = new String(chars);
        Map<String, Object> obj = new LinkedHashMap<>();
        if ("value".equals(where)) {
            obj.put("s", s);
        } else {
            obj.put(s, 1L);
        }
        return obj;
    }

    private static String sha256Hex(String s) {
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256")
                .digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Malformed-request marker: a protocol error, NOT a canonicalJson
     *  rejection. */
    static final class RequestError extends Exception {
        RequestError(String message) {
            super(message);
        }
    }

    /** Build a Java String from UTF-16 code units, leaving lone surrogates
     *  intact (Java char[] permits them). */
    private static String utf16UnitsToString(List<Object> units) {
        if (units == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Object u : units) {
            long n = ((Number) u).longValue();
            sb.append((char) (n & 0xFFFF));
        }
        return sb.toString();
    }

    private static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int read;
        while ((read = in.read(chunk)) != -1) {
            buf.write(chunk, 0, read);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }
}
