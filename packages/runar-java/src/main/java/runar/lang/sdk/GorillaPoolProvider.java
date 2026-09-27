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
    private final RawFetcher rawFetcher;

    /**
     * Binary GET seam for {@code /tx/{txid}/raw}. {@link HttpTransport} decodes
     * bodies as text, which would corrupt a serialized transaction.
     */
    interface RawFetcher {
        RawResponse get(String url);
    }

    /** Binary HTTP response holder for {@link RawFetcher}. */
    record RawResponse(int statusCode, byte[] body) {}

    /** Explicitly selects mainnet. Use {@link #GorillaPoolProvider(String)} to choose. */
    public GorillaPoolProvider() {
        this("mainnet", HttpTransport.jdkDefault());
    }

    public GorillaPoolProvider(String network) {
        this(network, HttpTransport.jdkDefault());
    }

    // Package-private constructor so tests can inject a fake transport.
    GorillaPoolProvider(String network, HttpTransport transport) {
        this(network, transport, null);
    }

    // Package-private full constructor so tests can also inject a fake binary fetcher.
    GorillaPoolProvider(String network, HttpTransport transport, RawFetcher rawFetcher) {
        // Network must be exactly "mainnet" or "testnet". Any other value —
        // including null and the empty string — is rejected rather than
        // defaulted, so a typo or an unvalidated user-supplied value can never
        // silently point the SDK at live mainnet.
        if (!"mainnet".equals(network) && !"testnet".equals(network)) {
            throw new IllegalArgumentException(
                "invalid network " + (network == null ? "null" : "\"" + network + "\"")
                    + ": must be \"mainnet\" or \"testnet\"");
        }
        this.network = network;
        this.baseUrl = "testnet".equals(network)
            ? "https://testnet.ordinals.gorillapool.io/api"
            : "https://ordinals.gorillapool.io/api";
        this.transport = transport == null ? HttpTransport.jdkDefault() : transport;
        this.rawFetcher = rawFetcher == null ? GorillaPoolProvider::jdkGetBytes : rawFetcher;
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

        List<UTXO> utxos = parseUtxoList(resp.body(), "GorillaPool getUtxos");
        // DoS-bound: reject pathological scripts at the provider boundary.
        for (UTXO u : utxos) {
            if (u.scriptHex() == null || u.scriptHex().isEmpty()) continue;
            ScriptSizeExceededError.assertScriptHexUnderLimit(
                u.scriptHex(), InputLimits.MAX_SCRIPT_BYTES,
                "GorillaPoolProvider.listUtxos(" + address + ")"
            );
        }
        return utxos;
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

    /**
     * Fetches the transaction via {@code /tx/{txid}/raw} (the bare serialized
     * transaction) and returns output {@code vout}. The satoshis are read from
     * the output's 8-byte little-endian field, so the value is exact (F-027:
     * the former JSON {@code vout[].value} decode with its {@code < 1000 → BTC}
     * guess targeted a field GorillaPool never returns). The body must hash to
     * the requested txid. Returns {@code null} on 404 or an out-of-range vout.
     */
    @Override
    public UTXO getUtxo(String txid, int vout) {
        RawResponse resp = rawFetcher.get(baseUrl + "/tx/" + txid + "/raw");
        if (resp.statusCode() == 404) return null;
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            String body = resp.body() == null ? "" : new String(resp.body(), StandardCharsets.UTF_8);
            throw new ProviderException("GorillaPool getTransaction failed (" + resp.statusCode() + "): "
                + RPCProvider.truncate(body, 256), resp.statusCode());
        }
        byte[] raw = resp.body() == null ? new byte[0] : resp.body();
        String bodyTxid = ScriptUtils.reverseHex(ScriptUtils.bytesToHex(Hash160.doubleSha256(raw)));
        if (!bodyTxid.equals(txid.toLowerCase(java.util.Locale.ROOT))) {
            throw new ProviderException("GorillaPool getTransaction: txid mismatch: response body hashes to "
                + bodyTxid + ", requested " + txid);
        }
        RawTx tx;
        try {
            tx = RawTxParser.parse(ScriptUtils.bytesToHex(raw));
        } catch (RuntimeException re) {
            throw new ProviderException("GorillaPool getTransaction: parsing tx: " + re.getMessage(), re);
        }
        if (vout < 0 || vout >= tx.outputs.size()) return null;
        RawTx.Output out = tx.outputs.get(vout);
        String script = out.scriptPubKeyHex == null ? "" : out.scriptPubKeyHex;
        if (!script.isEmpty()) {
            ScriptSizeExceededError.assertScriptHexUnderLimit(
                script, InputLimits.MAX_SCRIPT_BYTES,
                "GorillaPoolProvider.getUtxo(" + txid + ":" + vout + ")"
            );
        }
        return new UTXO(bodyTxid, vout, out.satoshis, script);
    }

    /** Default {@link RawFetcher}: a JDK HttpClient GET that keeps the body as bytes. */
    private static RawResponse jdkGetBytes(String url) {
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
            .uri(java.net.URI.create(url))
            .timeout(java.time.Duration.ofMinutes(10))
            .GET()
            .build();
        try {
            java.net.http.HttpResponse<byte[]> resp = RAW_CLIENT.send(
                req, java.net.http.HttpResponse.BodyHandlers.ofByteArray());
            return new RawResponse(resp.statusCode(), resp.body() == null ? new byte[0] : resp.body());
        } catch (java.io.IOException ioe) {
            throw new ProviderException("HTTP GET " + url + " failed: " + ioe.getMessage(), ioe);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new ProviderException("HTTP GET " + url + " interrupted", ie);
        }
    }

    private static final java.net.http.HttpClient RAW_CLIENT = java.net.http.HttpClient.newBuilder()
        .connectTimeout(java.time.Duration.ofSeconds(30))
        .build();

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
