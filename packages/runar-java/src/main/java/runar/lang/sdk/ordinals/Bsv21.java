package runar.lang.sdk.ordinals;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import runar.lang.sdk.Inscription;
import runar.lang.sdk.Json;

/**
 * BSV-21 (v2) — ID-based fungible-token inscription helpers (the
 * "stateful" variant of BSV-20). Mirrors {@code bsv21*} in
 * {@code packages/runar-zig/src/sdk_ordinals.zig},
 * {@code BSV21} in {@code packages/runar-sdk/src/ordinals/bsv20.ts},
 * and {@code Runar::SDK::Ordinals.bsv21_*} in
 * {@code packages/runar-rb/lib/runar/sdk/ordinals.rb}.
 *
 * <p>BSV-21 reuses the {@code application/bsv-20} content type and the
 * same inscription envelope, but distinguishes operations by their
 * field shape:
 * <pre>
 *   {"p":"bsv-20","op":"deploy+mint","amt":"1000000","sym":"RNR","dec":"18"}
 *   {"p":"bsv-20","op":"transfer","id":"&lt;txid&gt;_&lt;vout&gt;","amt":"100"}
 * </pre>
 * The token identity is the {@code &lt;txid&gt;_&lt;vout&gt;} of the
 * deploy+mint output, computed once the genesis transaction is
 * broadcast — it does <em>not</em> appear in the genesis JSON itself.
 */
public final class Bsv21 {

    private Bsv21() {}

    // ------------------------------------------------------------------
    // BSV-21 op record (parse result)
    // ------------------------------------------------------------------

    /**
     * Decoded BSV-21 operation.
     *
     * <ul>
     *     <li>For {@code deploy+mint}: {@code amt} is required;
     *         {@code sym}, {@code dec}, {@code icon} optional.</li>
     *     <li>For {@code transfer}: {@code id} and {@code amt} required.</li>
     * </ul>
     */
    public record Op(
        String p,
        String op,
        String id,
        String sym,
        String dec,
        String icon,
        String amt
    ) {}

    // ------------------------------------------------------------------
    // Build
    // ------------------------------------------------------------------

    /**
     * Build a BSV-21 deploy+mint genesis inscription. The on-chain
     * token id of the resulting deployment is
     * {@code <txid>_<vout>} of the output containing this inscription
     * once the deploy transaction is broadcast — it is <em>not</em>
     * encoded in the genesis JSON itself, so the {@code tokenId}
     * argument is accepted only for caller convenience and does not
     * change the byte-level output. Pass {@code null} or an empty
     * string when the id is not yet known.
     *
     * @param symbol         token symbol; written as {@code "sym"} when non-null
     * @param initialSupply  initial mint amount; decimal-stringified for the wire
     * @param tokenId        ignored for envelope output (see above)
     */
    public static Inscription deploy(String symbol, long initialSupply, String tokenId) {
        Map<String, String> obj = new LinkedHashMap<>();
        obj.put("p", "bsv-20");
        obj.put("op", "deploy+mint");
        obj.put("amt", Long.toString(initialSupply));
        if (symbol != null && !symbol.isEmpty()) obj.put("sym", symbol);
        // tokenId intentionally omitted — see method javadoc.
        return Bsv20.jsonInscription(obj);
    }

    /**
     * Full deploy+mint signature including {@code dec} and {@code icon}.
     * Matches the canonical {@code BSV21.deployMint} call across SDKs.
     */
    public static Inscription deployMint(String amount, String decimals, String symbol, String icon) {
        Map<String, String> obj = new LinkedHashMap<>();
        obj.put("p", "bsv-20");
        obj.put("op", "deploy+mint");
        obj.put("amt", amount);
        if (decimals != null) obj.put("dec", decimals);
        if (symbol != null) obj.put("sym", symbol);
        if (icon != null) obj.put("icon", icon);
        return Bsv20.jsonInscription(obj);
    }

    /**
     * Build a BSV-21 transfer inscription.
     *
     * @param tokenId token id (format: {@code "<txid>_<vout>"})
     * @param amount  transfer amount; decimal-stringified for the wire
     */
    public static Inscription transfer(String tokenId, long amount) {
        return transfer(tokenId, Long.toString(amount));
    }

    /** String-amount overload of {@link #transfer(String, long)}. */
    public static Inscription transfer(String tokenId, String amount) {
        Map<String, String> obj = new LinkedHashMap<>();
        obj.put("p", "bsv-20");
        obj.put("op", "transfer");
        obj.put("id", tokenId);
        obj.put("amt", amount);
        return Bsv20.jsonInscription(obj);
    }

    // ------------------------------------------------------------------
    // Parse
    // ------------------------------------------------------------------

    /** Parse the raw BSV-21 inscription bytes (UTF-8 JSON). */
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
        // BSV-21 ops: "deploy+mint" or "transfer" (with "id" set). We
        // accept any op here and let callers discriminate; for
        // "transfer" without "id" the result will have id == null,
        // which is the BSV-20 transfer shape.
        return new Op(
            p,
            op,
            stringField(m, "id"),
            stringField(m, "sym"),
            stringField(m, "dec"),
            stringField(m, "icon"),
            stringField(m, "amt")
        );
    }

    private static String stringField(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v instanceof String s ? s : null;
    }
}
