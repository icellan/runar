package runar.lang.sdk;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REST {@link Provider} backed by the GorillaPool 1sat Ordinals API.
 * Parity with {@code packages/runar-go/sdk_gorillapool.go}.
 *
 * <p>Endpoints:
 * <ul>
 *     <li>Mainnet: {@code https://ordinals.gorillapool.io/api}</li>
 *     <li>Testnet: {@code https://testnet.ordinals.gorillapool.io/api}</li>
 * </ul>
 *
 * <p>UTXO endpoints return objects with {@code txid}, {@code vout},
 * {@code satoshis}, and (optional) {@code script} keys. The broadcast
 * endpoint accepts a {@code {"rawTx":"..."}} body and may return either a
 * JSON-encoded txid string or a {@code {"txid":"..."}} envelope; both
 * forms are tolerated.
 */
public final class GorillaPoolProvider implements Provider {

    private final String network;
    private final String baseUrl;
    private final HttpTransport transport;

    public GorillaPoolProvider() {
        this("mainnet", HttpTransport.jdkDefault());
    }

    public GorillaPoolProvider(String network) {
        this(network, HttpTransport.jdkDefault());
    }

    // Package-private full constructor so tests can inject a fake transport.
    GorillaPoolProvider(String network, HttpTransport transport) {
        String n = (network == null || network.isEmpty()) ? "mainnet" : network;
        this.network = n;
        this.baseUrl = "testnet".equals(n)
            ? "https://testnet.ordinals.gorillapool.io/api"
            : "https://ordinals.gorillapool.io/api";
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
            "GET", baseUrl + "/address/" + address + "/utxos", null, null);
        if (resp.statusCode() == 404) return List.of();
        requireOk(resp, "GorillaPool getUtxos");

        return parseUtxoList(resp.body(), "GorillaPool getUtxos");
    }

    @Override
    public String broadcastRaw(String txHex) {
        if (txHex == null || txHex.isEmpty()) {
            throw new IllegalArgumentException("GorillaPoolProvider.broadcastRaw: txHex is required");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("rawTx", txHex);
        Map<String, String> headers = Map.of("Content-Type", "application/json");

        HttpTransport.Response resp = transport.send(
            "POST", baseUrl + "/tx", headers, JsonWriter.write(payload));
        requireOk(resp, "GorillaPool broadcast");

        String body = resp.body() == null ? "" : resp.body().trim();
        // Try JSON-encoded string first, then {"txid": "..."}, then raw text.
        try {
            Object parsed = Json.parse(body);
            if (parsed instanceof String s) return s;
            if (parsed instanceof Map<?, ?> m) {
                Object t = ((Map<?, ?>) m).get("txid");
                if (t instanceof String s && !s.isEmpty()) return s;
            }
        } catch (RuntimeException ignored) {
            // Fall through to plain-text body.
        }
        return body;
    }

    @Override
    public UTXO getUtxo(String txid, int vout) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/tx/" + txid, null, null);
        if (resp.statusCode() == 404) return null;
        requireOk(resp, "GorillaPool getTransaction");

        Map<String, Object> data = Json.asObject(parseJson(resp.body(), "GorillaPool getTransaction"));
        Object voutArr = data.get("vout");
        if (!(voutArr instanceof List<?> outs) || vout < 0 || vout >= outs.size()) return null;
        Map<String, Object> out = Json.asObject(outs.get(vout));
        long sats = btcOrSatToSatoshis(out.get("value"));
        String script = "";
        if (out.get("scriptPubKey") instanceof Map<?, ?> sp) {
            Object hex = ((Map<?, ?>) sp).get("hex");
            if (hex instanceof String s) script = s;
        }
        return new UTXO(txid, vout, sats, script);
    }

    /**
     * Fetches the raw transaction hex by txid via {@code /tx/{txid}/hex}.
     * Mirrors {@code GorillaPoolProvider.GetRawTransaction} in the Go SDK.
     */
    public String getRawTransaction(String txid) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/tx/" + txid + "/hex", null, null);
        requireOk(resp, "GorillaPool getRawTransaction");
        return resp.body() == null ? "" : resp.body().trim();
    }

    /**
     * Looks up unspent outputs for a script hash via
     * {@code /script/{scriptHash}/utxos}. Returns an empty list when the
     * upstream returns 404. Useful for stateful contract continuations.
     */
    public List<UTXO> getContractUtxos(String scriptHash) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/script/" + scriptHash + "/utxos", null, null);
        if (resp.statusCode() == 404) return List.of();
        requireOk(resp, "GorillaPool getContractUtxos");
        return parseUtxoList(resp.body(), "GorillaPool getContractUtxos");
    }

    // ------------------------------------------------------------------
    // Ordinal / token helpers (parity with Go SDK)
    // ------------------------------------------------------------------

    /** {@code /bsv20/balance/{address}/{tick}} — returns the balance string, or "0". */
    public String getBSV20Balance(String address, String tick) {
        return getTokenBalance(address, tick, "getBSV20Balance");
    }

    /** {@code /bsv20/utxos/{address}/{tick}}. */
    public List<UTXO> getBSV20Utxos(String address, String tick) {
        return getTokenUtxos(address, tick, "getBSV20Utxos");
    }

    /** {@code /bsv20/balance/{address}/{id}} — id is {@code <txid>_<vout>}. */
    public String getBSV21Balance(String address, String id) {
        return getTokenBalance(address, id, "getBSV21Balance");
    }

    /** {@code /bsv20/utxos/{address}/{id}} — id is {@code <txid>_<vout>}. */
    public List<UTXO> getBSV21Utxos(String address, String id) {
        return getTokenUtxos(address, id, "getBSV21Utxos");
    }

    private String getTokenBalance(String address, String key, String op) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/bsv20/balance/" + address + "/" + urlEncode(key), null, null);
        if (resp.statusCode() == 404) return "0";
        requireOk(resp, "GorillaPool " + op);

        String body = resp.body() == null ? "" : resp.body().trim();
        try {
            Object parsed = Json.parse(body);
            if (parsed instanceof String s) return s;
            if (parsed instanceof Map<?, ?> m) {
                Object bal = ((Map<?, ?>) m).get("balance");
                if (bal instanceof String s && !s.isEmpty()) return s;
            }
        } catch (RuntimeException ignored) {
            // Fall through.
        }
        return "0";
    }

    private List<UTXO> getTokenUtxos(String address, String key, String op) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/bsv20/utxos/" + address + "/" + urlEncode(key), null, null);
        if (resp.statusCode() == 404) return List.of();
        requireOk(resp, "GorillaPool " + op);
        return parseUtxoList(resp.body(), "GorillaPool " + op);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static List<UTXO> parseUtxoList(String body, String op) {
        Object parsed = parseJson(body, op);
        if (!(parsed instanceof List<?> entries)) {
            throw new ProviderException(op + ": expected JSON array, got " + typeName(parsed));
        }
        List<UTXO> utxos = new ArrayList<>(entries.size());
        for (Object e : entries) {
            Map<String, Object> u = Json.asObject(e);
            String txid = Json.asString(u.get("txid"));
            int vout = Json.asInt(u.get("vout"));
            long sats = Json.asLong(u.get("satoshis"));
            String script = "";
            if (u.get("script") instanceof String s) script = s;
            utxos.add(new UTXO(txid, vout, sats, script));
        }
        return utxos;
    }

    private static long btcOrSatToSatoshis(Object value) {
        if (value == null) return 0L;
        if (value instanceof Double d) {
            // GorillaPool may serialize as raw satoshis (integer-shaped doubles)
            // or as BTC. Mirror the Go SDK heuristic: < 1000 means BTC.
            if (d < 1000.0) return Math.round(d * 1e8);
            return d.longValue();
        }
        if (value instanceof Long l) return l;
        if (value instanceof Integer i) return i;
        if (value instanceof java.math.BigInteger bi) return bi.longValueExact();
        if (value instanceof String s) {
            double parsed = Double.parseDouble(s);
            if (parsed < 1000.0) return Math.round(parsed * 1e8);
            return (long) parsed;
        }
        throw new ProviderException("expected numeric vout.value, got " + typeName(value));
    }

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

    private static String urlEncode(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    private static String typeName(Object v) {
        return v == null ? "null" : v.getClass().getSimpleName();
    }
}
