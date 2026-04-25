package runar.lang.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REST {@link Provider} backed by the WhatsOnChain BSV API.
 * Parity with {@code packages/runar-go/sdk_woc_provider.go}.
 *
 * <p>Endpoints:
 * <ul>
 *     <li>Mainnet: {@code https://api.whatsonchain.com/v1/bsv/main}</li>
 *     <li>Testnet: {@code https://api.whatsonchain.com/v1/bsv/test}</li>
 * </ul>
 *
 * <p>{@link #listUtxos(String)} hits {@code /address/{addr}/unspent} (returns
 * outpoints + values; the locking script is not in the listing — fetch via
 * {@link #getUtxo(String, int)} when needed). {@link #broadcastRaw(String)}
 * POSTs to {@code /tx/raw} with a {@code {"txhex":"..."}} body. WoC returns
 * the txid as a JSON-encoded string.
 */
public final class WhatsOnChainProvider implements Provider {

    private final String network;
    private final String baseUrl;
    private final HttpTransport transport;

    /** Defaults to mainnet when {@code network} is null/empty. */
    public WhatsOnChainProvider() {
        this("mainnet", HttpTransport.jdkDefault());
    }

    public WhatsOnChainProvider(String network) {
        this(network, HttpTransport.jdkDefault());
    }

    // Package-private full constructor so tests can inject a fake transport.
    WhatsOnChainProvider(String network, HttpTransport transport) {
        String n = (network == null || network.isEmpty()) ? "mainnet" : network;
        this.network = n;
        this.baseUrl = "testnet".equals(n)
            ? "https://api.whatsonchain.com/v1/bsv/test"
            : "https://api.whatsonchain.com/v1/bsv/main";
        this.transport = transport == null ? HttpTransport.jdkDefault() : transport;
    }

    public String getNetwork() {
        return network;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    // ------------------------------------------------------------------
    // Provider
    // ------------------------------------------------------------------

    @Override
    public List<UTXO> listUtxos(String address) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/address/" + address + "/unspent", null, null);
        if (resp.statusCode() == 404) return List.of();
        requireOk(resp, "WoC getUtxos");

        Object parsed = parseJson(resp.body(), "WoC getUtxos");
        if (!(parsed instanceof List<?> entries)) {
            throw new ProviderException("WoC getUtxos: expected JSON array, got " + typeName(parsed));
        }
        List<UTXO> utxos = new ArrayList<>(entries.size());
        for (Object e : entries) {
            Map<String, Object> u = Json.asObject(e);
            String txid = Json.asString(u.get("tx_hash"));
            int pos = Json.asInt(u.get("tx_pos"));
            long value = Json.asLong(u.get("value"));
            // WoC's UTXO listing does not include the locking script.
            utxos.add(new UTXO(txid, pos, value, ""));
        }
        return utxos;
    }

    @Override
    public String broadcastRaw(String txHex) {
        if (txHex == null || txHex.isEmpty()) {
            throw new IllegalArgumentException("WhatsOnChainProvider.broadcastRaw: txHex is required");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("txhex", txHex);
        Map<String, String> headers = Map.of("Content-Type", "application/json");

        HttpTransport.Response resp = transport.send(
            "POST", baseUrl + "/tx/raw", headers, JsonWriter.write(payload));
        requireOk(resp, "WoC broadcast");

        // WoC returns the txid as a JSON-encoded string ("\"abcd...\"").
        Object parsed = parseJson(resp.body(), "WoC broadcast");
        if (!(parsed instanceof String txid)) {
            throw new ProviderException("WoC broadcast: expected JSON string, got " + typeName(parsed));
        }
        return txid;
    }

    @Override
    public UTXO getUtxo(String txid, int vout) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/tx/hash/" + txid, null, null);
        if (resp.statusCode() == 404) return null;
        requireOk(resp, "WoC getTransaction");

        Map<String, Object> data = Json.asObject(parseJson(resp.body(), "WoC getTransaction"));
        Object voutArr = data.get("vout");
        if (!(voutArr instanceof List<?> outs) || vout < 0 || vout >= outs.size()) return null;
        Map<String, Object> out = Json.asObject(outs.get(vout));
        Object value = out.get("value");
        long sats;
        if (value instanceof Double d) {
            sats = Math.round(d * 1e8);
        } else if (value instanceof Long l) {
            sats = l;
        } else if (value instanceof Integer i) {
            sats = i;
        } else {
            throw new ProviderException("WoC getTransaction: unexpected vout.value type " + typeName(value));
        }
        String script = "";
        if (out.get("scriptPubKey") instanceof Map<?, ?> sp) {
            Object hex = ((Map<?, ?>) sp).get("hex");
            if (hex instanceof String s) script = s;
        }
        return new UTXO(txid, vout, sats, script);
    }

    /**
     * Fetches the raw transaction hex by txid via {@code /tx/{txid}/hex}.
     * Mirrors {@code WhatsOnChainProvider.GetRawTransaction} in the Go SDK.
     */
    public String getRawTransaction(String txid) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/tx/" + txid + "/hex", null, null);
        requireOk(resp, "WoC getRawTransaction");
        return resp.body() == null ? "" : resp.body().trim();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static void requireOk(HttpTransport.Response resp, String op) {
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new ProviderException(
                op + " failed (" + resp.statusCode() + "): "
                    + RPCProvider.truncate(resp.body(), 256),
                resp.statusCode());
        }
    }

    private static Object parseJson(String body, String op) {
        try {
            return Json.parse(body);
        } catch (RuntimeException re) {
            throw new ProviderException(op + " JSON decode failed: " + re.getMessage(), re);
        }
    }

    private static String typeName(Object v) {
        return v == null ? "null" : v.getClass().getSimpleName();
    }
}
