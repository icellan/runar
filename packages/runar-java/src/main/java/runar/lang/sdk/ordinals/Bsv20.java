package runar.lang.sdk.ordinals;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import runar.lang.sdk.Inscription;
import runar.lang.sdk.Json;
import runar.lang.sdk.JsonWriter;

/**
 * BSV-20 (v1) — tick-based fungible-token inscription helpers.
 *
 * <p>Mirrors the Zig {@code sdk_ordinals.zig} {@code bsv20*} helpers,
 * the TS {@code BSV20} object in {@code packages/runar-sdk}, and the
 * Ruby {@code Runar::SDK::Ordinals.bsv20_*} module functions. The JSON
 * payload of the produced inscription is byte-identical across all
 * six SDKs so that round-tripping an envelope through any
 * implementation yields the same on-chain bytes.
 *
 * <p>BSV-20 wire format wraps a small JSON document in a 1sat ordinals
 * envelope with content type {@code application/bsv-20}:
 * <pre>
 *   {"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000","lim":"1000","dec":"0"}
 *   {"p":"bsv-20","op":"mint","tick":"RUNAR","amt":"1000"}
 *   {"p":"bsv-20","op":"transfer","tick":"RUNAR","amt":"50"}
 * </pre>
 *
 * <p>All numeric fields ({@code max}, {@code lim}, {@code amt},
 * {@code dec}) are JSON strings — BSV-20 has no native numeric type,
 * which keeps the envelope safe for arbitrary-precision token amounts.
 */
public final class Bsv20 {

    /** MIME type used by the BSV-20 / BSV-21 inscription envelope. */
    public static final String CONTENT_TYPE = "application/bsv-20";

    private Bsv20() {}

    // ------------------------------------------------------------------
    // BSV-20 op record (parse result)
    // ------------------------------------------------------------------

    /**
     * Decoded BSV-20 operation. {@code op} is one of {@code "deploy"},
     * {@code "mint"}, or {@code "transfer"}; {@code tick} is set on all
     * three; {@code max}, {@code lim}, {@code dec}, {@code amt} are
     * populated where the source op carries them.
     *
     * <p>String-valued fields keep the on-chain BSV-20 numeric semantics
     * (arbitrary-precision decimal). Callers that need a {@code long}
     * can use {@link Long#parseLong(String)} after validating ranges.
     */
    public record Op(
        String p,
        String op,
        String tick,
        String max,
        String lim,
        String dec,
        String amt
    ) {}

    // ------------------------------------------------------------------
    // Build
    // ------------------------------------------------------------------

    /**
     * Build a BSV-20 deploy inscription. Numeric arguments are
     * decimal-stringified to match the canonical wire shape.
     *
     * @param ticker      ticker symbol (e.g. {@code "RUNAR"})
     * @param maxSupply   total maximum supply
     * @param mintLimit   per-mint limit; {@code 0} or negative omits {@code lim}
     * @param decimals    decimal places; negative omits {@code dec}
     */
    public static Inscription deploy(String ticker, long maxSupply, long mintLimit, int decimals) {
        Map<String, String> obj = new LinkedHashMap<>();
        obj.put("p", "bsv-20");
        obj.put("op", "deploy");
        obj.put("tick", ticker);
        obj.put("max", Long.toString(maxSupply));
        if (mintLimit > 0) obj.put("lim", Long.toString(mintLimit));
        if (decimals >= 0) obj.put("dec", Integer.toString(decimals));
        return jsonInscription(obj);
    }

    /**
     * Build a BSV-20 deploy inscription with string-valued fields,
     * matching the TS / Go / Ruby cross-SDK signature exactly. Useful
     * when token amounts exceed {@link Long#MAX_VALUE}.
     */
    public static Inscription deploy(String ticker, String maxSupply, String mintLimit, String decimals) {
        Map<String, String> obj = new LinkedHashMap<>();
        obj.put("p", "bsv-20");
        obj.put("op", "deploy");
        obj.put("tick", ticker);
        obj.put("max", maxSupply);
        if (mintLimit != null) obj.put("lim", mintLimit);
        if (decimals != null) obj.put("dec", decimals);
        return jsonInscription(obj);
    }

    /**
     * Build a BSV-20 mint inscription.
     *
     * @param ticker ticker symbol of the previously-deployed token
     * @param amount mint amount; passed as a decimal string on the wire
     */
    public static Inscription mint(String ticker, long amount) {
        return mint(ticker, Long.toString(amount));
    }

    /** String-amount overload of {@link #mint(String, long)}. */
    public static Inscription mint(String ticker, String amount) {
        Map<String, String> obj = new LinkedHashMap<>();
        obj.put("p", "bsv-20");
        obj.put("op", "mint");
        obj.put("tick", ticker);
        obj.put("amt", amount);
        return jsonInscription(obj);
    }

    /**
     * Build a BSV-20 transfer inscription.
     *
     * @param ticker ticker symbol
     * @param amount transfer amount; decimal-stringified for the wire
     */
    public static Inscription transfer(String ticker, long amount) {
        return transfer(ticker, Long.toString(amount));
    }

    /** String-amount overload of {@link #transfer(String, long)}. */
    public static Inscription transfer(String ticker, String amount) {
        Map<String, String> obj = new LinkedHashMap<>();
        obj.put("p", "bsv-20");
        obj.put("op", "transfer");
        obj.put("tick", ticker);
        obj.put("amt", amount);
        return jsonInscription(obj);
    }

    // ------------------------------------------------------------------
    // Parse
    // ------------------------------------------------------------------

    /**
     * Parse a BSV-20 inscription's UTF-8 / JSON payload. The argument
     * is the raw inscription bytes (the decoded {@code data} field of
     * an {@link Inscription}, not the wrapped envelope hex).
     *
     * @return decoded {@link Op}, or {@code null} if the payload is not
     *         a valid BSV-20 JSON document with {@code "p":"bsv-20"}
     */
    public static Op parse(byte[] inscription) {
        if (inscription == null || inscription.length == 0) return null;
        return parseJson(new String(inscription, StandardCharsets.UTF_8));
    }

    /** Convenience overload taking the JSON text directly. */
    public static Op parse(String json) {
        if (json == null || json.isEmpty()) return null;
        return parseJson(json);
    }

    private static Op parseJson(String json) {
        Object tree;
        try {
            tree = Json.parse(json);
        } catch (RuntimeException e) {
            return null;
        }
        if (!(tree instanceof Map<?, ?> raw)) return null;
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) raw;

        String p = stringField(m, "p");
        if (!"bsv-20".equals(p)) return null;
        String op = stringField(m, "op");
        if (op == null) return null;
        return new Op(
            p,
            op,
            stringField(m, "tick"),
            stringField(m, "max"),
            stringField(m, "lim"),
            stringField(m, "dec"),
            stringField(m, "amt")
        );
    }

    private static String stringField(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v instanceof String s ? s : null;
    }

    // ------------------------------------------------------------------
    // Helpers shared with Bsv21
    // ------------------------------------------------------------------

    static Inscription jsonInscription(Map<String, String> obj) {
        String json = JsonWriter.write(obj);
        byte[] utf8 = json.getBytes(StandardCharsets.UTF_8);
        return new Inscription(CONTENT_TYPE, bytesToHex(utf8));
    }

    static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) {
            sb.append(Character.forDigit((v >> 4) & 0xf, 16));
            sb.append(Character.forDigit(v & 0xf, 16));
        }
        return sb.toString();
    }
}
