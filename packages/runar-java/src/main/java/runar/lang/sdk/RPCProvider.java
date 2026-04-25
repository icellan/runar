package runar.lang.sdk;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bitcoin-Core / SV-Node compatible JSON-RPC {@link Provider}. Parity with
 * {@code packages/runar-go/rpc_provider.go} {@code RPCProvider}.
 *
 * <p>Methods used:
 * <ul>
 *     <li>{@code listunspent} for {@link #listUtxos(String)}</li>
 *     <li>{@code sendrawtransaction} for {@link #broadcastRaw(String)}</li>
 *     <li>{@code getrawtransaction} (verbose) for {@link #getUtxo(String, int)}</li>
 *     <li>{@code generate} / {@code generatetoaddress} for regtest auto-mining</li>
 * </ul>
 *
 * <p>Authentication is HTTP Basic over the {@code Authorization} header.
 * Failures (transport, non-2xx, JSON-RPC error envelope) raise
 * {@link ProviderException}.
 */
public final class RPCProvider implements Provider {

    private final String url;
    private final String user;
    private final String pass;
    private final String network;
    private final boolean autoMine;
    private final HttpTransport transport;
    private final AtomicLong rpcId = new AtomicLong();

    /** Standard provider — defaults to {@code "testnet"}, no auto-mine. */
    public RPCProvider(String url, String user, String pass) {
        this(url, user, pass, "testnet", false, HttpTransport.jdkDefault());
    }

    /** Regtest convenience — auto-mines 1 block after every broadcast. */
    public static RPCProvider regtest(String url, String user, String pass) {
        return new RPCProvider(url, user, pass, "regtest", true, HttpTransport.jdkDefault());
    }

    // Package-private full constructor so tests can inject a fake transport.
    RPCProvider(String url, String user, String pass, String network, boolean autoMine, HttpTransport transport) {
        if (url == null || url.isEmpty()) throw new IllegalArgumentException("RPCProvider: url is required");
        if (user == null) throw new IllegalArgumentException("RPCProvider: user is required");
        if (pass == null) throw new IllegalArgumentException("RPCProvider: pass is required");
        this.url = url;
        this.user = user;
        this.pass = pass;
        this.network = (network == null || network.isEmpty()) ? "testnet" : network;
        this.autoMine = autoMine;
        this.transport = transport == null ? HttpTransport.jdkDefault() : transport;
    }

    public String getNetwork() {
        return network;
    }

    public boolean isAutoMine() {
        return autoMine;
    }

    // ------------------------------------------------------------------
    // Provider
    // ------------------------------------------------------------------

    @Override
    public List<UTXO> listUtxos(String address) {
        Object result = rpcCall("listunspent",
            List.of(0L, 9_999_999L, List.of(address)));
        if (!(result instanceof List<?> entries)) {
            throw new ProviderException("listunspent: expected JSON array, got " + typeName(result));
        }
        List<UTXO> utxos = new ArrayList<>(entries.size());
        for (Object e : entries) {
            Map<String, Object> u = Json.asObject(e);
            String txid = Json.asString(u.get("txid"));
            int vout = Json.asInt(u.get("vout"));
            long sats = btcToSatoshis(u.get("amount"));
            String script = u.get("scriptPubKey") == null ? "" : Json.asString(u.get("scriptPubKey"));
            utxos.add(new UTXO(txid, vout, sats, script == null ? "" : script));
        }
        return utxos;
    }

    @Override
    public String broadcastRaw(String txHex) {
        if (txHex == null || txHex.isEmpty()) {
            throw new IllegalArgumentException("RPCProvider.broadcastRaw: txHex is required");
        }
        Object result = rpcCall("sendrawtransaction", List.of(txHex));
        if (!(result instanceof String txid)) {
            throw new ProviderException("sendrawtransaction: expected JSON string, got " + typeName(result));
        }
        if (autoMine) {
            try {
                mine(1);
            } catch (ProviderException pe) {
                // Mining failure is non-fatal — the tx was already broadcast.
                throw new ProviderException(
                    "broadcast succeeded (txid " + txid + ") but auto-mine failed: " + pe.getMessage(), pe);
            }
        }
        return txid;
    }

    @Override
    public UTXO getUtxo(String txid, int vout) {
        Object result;
        try {
            // verbose=1 so we get a structured response with vout values + scripts.
            result = rpcCall("getrawtransaction", List.of(txid, 1L));
        } catch (ProviderException pe) {
            // Not-found-style errors from the node should map to null, mirroring
            // MockProvider semantics. Anything else propagates.
            String msg = pe.getMessage() == null ? "" : pe.getMessage().toLowerCase();
            if (msg.contains("no such") || msg.contains("not found") || msg.contains("-5")) {
                return null;
            }
            throw pe;
        }
        Map<String, Object> raw = Json.asObject(result);
        Object voutArr = raw.get("vout");
        if (!(voutArr instanceof List<?> outputs)) return null;
        if (vout < 0 || vout >= outputs.size()) return null;
        Map<String, Object> out = Json.asObject(outputs.get(vout));
        long sats = btcToSatoshis(out.get("value"));
        String script = "";
        if (out.get("scriptPubKey") instanceof Map<?, ?> sp) {
            Object hex = ((Map<?, ?>) sp).get("hex");
            if (hex instanceof String s) script = s;
        }
        return new UTXO(txid, vout, sats, script);
    }

    /**
     * Fetches the raw (non-verbose) transaction hex by txid. Mirrors
     * the Go SDK's {@code GetRawTransaction}.
     */
    public String getRawTransaction(String txid) {
        Object result = rpcCall("getrawtransaction", List.of(txid, 0L));
        if (!(result instanceof String s)) {
            throw new ProviderException("getrawtransaction: expected JSON string, got " + typeName(result));
        }
        return s;
    }

    // ------------------------------------------------------------------
    // JSON-RPC plumbing (package-private for tests)
    // ------------------------------------------------------------------

    Object rpcCall(String method, List<?> params) {
        long id = rpcId.incrementAndGet();
        String body = encodeRpcRequest(id, method, params);
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", "Basic " +
            Base64.getEncoder().encodeToString((user + ":" + pass).getBytes()));

        HttpTransport.Response resp = transport.send("POST", url, headers, body);
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            // SV-Node returns 500 for errors with a JSON-RPC envelope body — try to
            // parse and surface the inner message rather than the raw status code.
            String inner = tryExtractRpcError(resp.body());
            if (inner != null) {
                throw new ProviderException("rpc " + method + ": " + inner, resp.statusCode());
            }
            throw new ProviderException(
                "rpc " + method + " HTTP " + resp.statusCode() + ": " + truncate(resp.body(), 256),
                resp.statusCode());
        }
        Object parsed;
        try {
            parsed = Json.parse(resp.body());
        } catch (RuntimeException re) {
            throw new ProviderException(
                "rpc " + method + " response parse error: " + re.getMessage()
                    + " (body: " + truncate(resp.body(), 256) + ")", re);
        }
        Map<String, Object> envelope = Json.asObject(parsed);
        Object err = envelope.get("error");
        if (err != null) {
            Map<String, Object> em = Json.asObject(err);
            int code = em.get("code") == null ? 0 : Json.asInt(em.get("code"));
            String msg = em.get("message") == null ? "" : Json.asString(em.get("message"));
            throw new ProviderException("rpc error " + code + ": " + msg);
        }
        return envelope.get("result");
    }

    private static String tryExtractRpcError(String body) {
        if (body == null || body.isEmpty()) return null;
        try {
            Object parsed = Json.parse(body);
            if (!(parsed instanceof Map<?, ?> m)) return null;
            Object err = m.get("error");
            if (!(err instanceof Map<?, ?> em)) return null;
            Object msg = em.get("message");
            return msg instanceof String s ? s : null;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    static String encodeRpcRequest(long id, String method, List<?> params) {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("jsonrpc", "1.0");
        req.put("id", "runar-" + id);
        req.put("method", method);
        req.put("params", params == null ? List.of() : params);
        return JsonWriter.write(req);
    }

    private void mine(int n) {
        try {
            rpcCall("generate", List.of((long) n));
            return;
        } catch (ProviderException ignored) {
            // Older nodes may not support `generate`; fall through to
            // generatetoaddress with a freshly-minted address.
        }
        Object addrResult = rpcCall("getnewaddress", List.of());
        if (!(addrResult instanceof String addr)) {
            throw new ProviderException("getnewaddress: expected JSON string, got " + typeName(addrResult));
        }
        rpcCall("generatetoaddress", List.of((long) n, addr));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static long btcToSatoshis(Object amount) {
        if (amount == null) return 0L;
        if (amount instanceof Double d) return Math.round(d * 1e8);
        if (amount instanceof Long l) return l * 100_000_000L;
        if (amount instanceof Integer i) return ((long) i) * 100_000_000L;
        if (amount instanceof java.math.BigInteger bi) return bi.longValueExact() * 100_000_000L;
        if (amount instanceof String s) {
            // Some nodes serialize amounts as strings to preserve precision.
            return Math.round(Double.parseDouble(s) * 1e8);
        }
        throw new ProviderException("expected numeric BTC amount, got " + typeName(amount));
    }

    private static String typeName(Object v) {
        return v == null ? "null" : v.getClass().getSimpleName();
    }

    static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }
}
