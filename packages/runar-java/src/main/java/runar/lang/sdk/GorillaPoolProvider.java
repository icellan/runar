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
 * <p>N-025: every method uses a route documented in the server's OpenAPI
 * document ({@code /txos/address/{a}/unspent}, {@code /tx/{txid}/raw},
 * {@code /bsv20/{a}/balance}, {@code /bsv20/{a}/tick/{tick}},
 * {@code /bsv20/{a}/id/{id}}, {@code POST /tx} with {@code {"rawtx":"..."}}),
 * and every non-2xx response — a 404 included — throws. The broadcast
 * response may be a JSON-encoded txid string or a {@code {"txid":"..."}}
 * envelope; both forms are tolerated.
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

    /**
     * N-025: {@code GET /txos/address/{address}/unspent} (Txo[]). The listing
     * carries no locking script, so each entry's tx is fetched via the
     * hash-verified {@code /tx/{txid}/raw}; the output must exist, its value
     * must equal the listing's, and its non-empty script is returned. Any
     * non-2xx (404 included) throws. Not filtered: 1-sat ordinal outputs are
     * returned too.
     */
    @Override
    public List<UTXO> listUtxos(String address) {
        String op = "GorillaPool getUtxos";
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/txos/address/" + address + "/unspent", null, null);
        requireOk(resp, op);
        Object parsed = parseJson(resp.body(), op);
        if (!(parsed instanceof List<?> entries)) {
            throw new ProviderException(op + ": expected JSON array, got " + typeName(parsed));
        }
        Map<String, RawTx> txs = new java.util.HashMap<>();
        List<UTXO> utxos = new ArrayList<>(entries.size());
        for (Object e : entries) {
            Map<String, Object> u = Json.asObject(e);
            String txid = Json.asString(u.get("txid"));
            int vout = Json.asInt(u.get("vout"));
            long sats = Json.asLong(u.get("satoshis"));
            RawTx tx = txs.get(txid);
            if (tx == null) {
                tx = parseRaw(fetchVerifiedRaw(txid, "getUtxos"), "getUtxos");
                txs.put(txid, tx);
            }
            if (vout < 0 || vout >= tx.outputs.size()) {
                throw new ProviderException(op + ": no output " + vout + " in tx " + txid
                    + " (" + tx.outputs.size() + " outputs)");
            }
            RawTx.Output out = tx.outputs.get(vout);
            if (out.satoshis != sats) {
                throw new ProviderException(op + ": value mismatch for " + txid + "_" + vout
                    + ": listing says " + sats + ", tx says " + out.satoshis);
            }
            String script = out.scriptPubKeyHex == null ? "" : out.scriptPubKeyHex;
            if (script.isEmpty()) {
                throw new ProviderException(op + ": empty locking script for " + txid + "_" + vout);
            }
            ScriptSizeExceededError.assertScriptHexUnderLimit(
                script, InputLimits.MAX_SCRIPT_BYTES,
                "GorillaPoolProvider.listUtxos(" + address + ")"
            );
            utxos.add(new UTXO(txid, vout, sats, script));
        }
        return utxos;
    }

    @Override
    public String broadcastRaw(String txHex) {
        if (txHex == null || txHex.isEmpty()) {
            throw new IllegalArgumentException("GorillaPoolProvider.broadcastRaw: txHex is required");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("rawtx", txHex); // N-025: the documented Broadcast body key
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
     * the requested txid. Returns {@code null} for an out-of-range vout (an
     * outpoint the tx does not have). N-025: any non-2xx — a 404 on this
     * documented route included — throws instead of returning {@code null}.
     */
    @Override
    public UTXO getUtxo(String txid, int vout) {
        byte[] raw = fetchVerifiedRaw(txid, "getTransaction");
        String bodyTxid = txid.toLowerCase(java.util.Locale.ROOT);
        RawTx tx = parseRaw(raw, "getTransaction");
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
     * N-025: fetches {@code /tx/{txid}/raw} (binary), refuses a body that does
     * not hash to {@code txid}, and returns it as lowercase hex. The former
     * {@code /tx/{txid}/hex} route does not exist.
     */
    public String getRawTransaction(String txid) {
        return ScriptUtils.bytesToHex(fetchVerifiedRaw(txid, "getRawTransaction"));
    }

    /**
     * N-025: the GorillaPool API has no documented route that looks UTXOs up
     * by script hash (the former {@code /script/{hash}/utxos} is a 404), so
     * this refuses without a request rather than reporting "no UTXOs".
     */
    public List<UTXO> getContractUtxos(String scriptHash) {
        throw new ProviderException("GorillaPool getContractUtxos(" + scriptHash
            + "): lookup by script hash is not supported by the GorillaPool API");
    }

    // ------------------------------------------------------------------
    // Ordinal / token helpers (parity with Go SDK)
    // ------------------------------------------------------------------

    /**
     * N-025: confirmed BSV-20 (v1) balance from {@code /bsv20/{address}/balance}:
     * the entry whose {@code tick} equals {@code tick} exactly, {@code all.confirmed};
     * "0" when the address holds no such token.
     */
    public String getBSV20Balance(String address, String tick) {
        return getTokenBalance(address, "tick", tick, "getBSV20Balance");
    }

    /** N-025: {@code /bsv20/{address}/tick/{tick}} (BSV20Txo[]). */
    public List<UTXO> getBSV20Utxos(String address, String tick) {
        return getTokenUtxos(baseUrl + "/bsv20/" + address + "/tick/" + urlEncode(tick), "getBSV20Utxos");
    }

    /** N-025: as {@link #getBSV20Balance} but matched on {@code id} ({@code <txid>_<vout>}). */
    public String getBSV21Balance(String address, String id) {
        return getTokenBalance(address, "id", id, "getBSV21Balance");
    }

    /** N-025: {@code /bsv20/{address}/id/{id}} (BSV20Txo[]); id is {@code <txid>_<vout>}. */
    public List<UTXO> getBSV21Utxos(String address, String id) {
        return getTokenUtxos(baseUrl + "/bsv20/" + address + "/id/" + urlEncode(id), "getBSV21Utxos");
    }

    private String getTokenBalance(String address, String field, String key, String op) {
        String what = "GorillaPool " + op;
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/bsv20/" + address + "/balance", null, null);
        requireOk(resp, what);
        Object parsed = parseJson(resp.body(), what);
        if (!(parsed instanceof List<?> rows)) {
            throw new ProviderException(what + ": expected JSON array, got " + typeName(parsed));
        }
        for (Object r : rows) {
            Map<String, Object> row = Json.asObject(r);
            if (key.equals(row.get(field))) {
                Object confirmed = Json.asObject(row.get("all")).get("confirmed");
                if (!(confirmed instanceof String s)) {
                    throw new ProviderException(what + ": all.confirmed is not a string for " + key);
                }
                return s;
            }
        }
        return "0";
    }

    private List<UTXO> getTokenUtxos(String url, String op) {
        String what = "GorillaPool " + op;
        HttpTransport.Response resp = transport.send("GET", url, null, null);
        requireOk(resp, what);
        Object parsed = parseJson(resp.body(), what);
        if (!(parsed instanceof List<?> entries)) {
            throw new ProviderException(what + ": expected JSON array, got " + typeName(parsed));
        }
        List<UTXO> utxos = new ArrayList<>(entries.size());
        for (Object e : entries) {
            Map<String, Object> u = Json.asObject(e);
            String txid = Json.asString(u.get("txid"));
            int vout = Json.asInt(u.get("vout"));
            long sats = Json.asLong(u.get("satoshis"));
            String script = "";
            if (u.get("script") instanceof String b64 && !b64.isEmpty()) {
                try {
                    script = ScriptUtils.bytesToHex(java.util.Base64.getDecoder().decode(b64));
                } catch (IllegalArgumentException iae) {
                    throw new ProviderException(what + ": script is not base64 for " + txid + "_" + vout, iae);
                }
            }
            if (script.isEmpty()) {
                throw new ProviderException(what + ": no locking script for " + txid + "_" + vout);
            }
            ScriptSizeExceededError.assertScriptHexUnderLimit(
                script, InputLimits.MAX_SCRIPT_BYTES, "GorillaPoolProvider." + op);
            utxos.add(new UTXO(txid, vout, sats, script));
        }
        return utxos;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** GET {@code /tx/{txid}/raw}; any non-2xx throws; the body must hash (sha256d, reversed) to txid. */
    private byte[] fetchVerifiedRaw(String txid, String op) {
        RawResponse resp = rawFetcher.get(baseUrl + "/tx/" + txid + "/raw");
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            String body = resp.body() == null ? "" : new String(resp.body(), StandardCharsets.UTF_8);
            throw new ProviderException("GorillaPool " + op + " failed (" + resp.statusCode() + "): "
                + RPCProvider.truncate(body, 256), resp.statusCode());
        }
        byte[] raw = resp.body() == null ? new byte[0] : resp.body();
        String bodyTxid = ScriptUtils.reverseHex(ScriptUtils.bytesToHex(Hash160.doubleSha256(raw)));
        if (!bodyTxid.equals(txid.toLowerCase(java.util.Locale.ROOT))) {
            throw new ProviderException("GorillaPool " + op + ": txid mismatch: response body hashes to "
                + bodyTxid + ", requested " + txid);
        }
        return raw;
    }

    private static RawTx parseRaw(byte[] raw, String op) {
        try {
            return RawTxParser.parse(ScriptUtils.bytesToHex(raw));
        } catch (RuntimeException re) {
            throw new ProviderException("GorillaPool " + op + ": parsing tx: " + re.getMessage(), re);
        }
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
