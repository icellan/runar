package runar.integration.helpers;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Minimal JSON-RPC client for a BSV regtest node. Mirrors the surface
 * of {@code integration/go/helpers/rpc.go} and
 * {@code integration/python/conftest.py::rpc_call}.
 *
 * <p>Two backends are supported:
 *
 * <ul>
 *   <li>{@code svnode}  — {@code bitcoinsv/bitcoin-sv:latest} regtest
 *       at {@code localhost:18332}</li>
 *   <li>{@code teranode} — BSV Teranode docker-compose stack at
 *       {@code localhost:19292}</li>
 * </ul>
 *
 * <p>Backend selection via the {@code BSV_BACKEND} (or {@code NODE_TYPE})
 * env var. Credentials and URL can be overridden with {@code RPC_URL},
 * {@code RPC_USER}, {@code RPC_PASS}.
 *
 * <p>The client uses a 30-minute timeout because mining 10,101 blocks
 * for Teranode Genesis activation or broadcasting a ~200 KB SLH-DSA
 * spending tx can easily take minutes.
 */
public final class RpcClient {

    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(30))
        .build();

    private static final AtomicLong REQ_ID = new AtomicLong(0);

    private final String url;
    private final String authHeader;
    private final String backend;

    public RpcClient() {
        this.backend = detectBackend();
        this.url = System.getenv().getOrDefault("RPC_URL", defaultUrl(backend));
        String user = System.getenv().getOrDefault("RPC_USER", "bitcoin");
        String pass = System.getenv().getOrDefault("RPC_PASS", "bitcoin");
        this.authHeader = "Basic " + Base64.getEncoder()
            .encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));
    }

    public String url() { return url; }
    public String backend() { return backend; }
    public boolean isTeranode() { return "teranode".equals(backend); }

    private static String detectBackend() {
        String v = System.getenv("BSV_BACKEND");
        if (v == null || v.isEmpty()) v = System.getenv("NODE_TYPE");
        if (v == null || v.isEmpty()) return "svnode";
        return v;
    }

    private static String defaultUrl(String backend) {
        return switch (backend) {
            case "teranode" -> "http://localhost:19292";
            default -> "http://localhost:18332";
        };
    }

    /**
     * Makes a JSON-RPC call with the given params (positional). Returns
     * the raw JSON text of the {@code result} field. Callers that need
     * typed access parse the result themselves using
     * {@link JsonReader}.
     *
     * <p>Parameter encoding: {@link String} values are quoted, {@link Boolean}
     * and {@link Number} are emitted as-is, lists are emitted as JSON arrays,
     * and {@code null} becomes JSON null. Unsupported types raise
     * {@link IllegalArgumentException}.
     */
    public String call(String method, Object... params) {
        long id = REQ_ID.incrementAndGet();
        StringBuilder body = new StringBuilder();
        body.append("{\"jsonrpc\":\"1.0\",\"id\":").append(id)
            .append(",\"method\":\"").append(method).append("\",\"params\":[");
        for (int i = 0; i < params.length; i++) {
            if (i > 0) body.append(',');
            body.append(encodeParam(params[i]));
        }
        body.append("]}");

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofMinutes(30))
            .header("Content-Type", "application/json")
            .header("Authorization", authHeader)
            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
            .build();

        HttpResponse<String> resp;
        try {
            resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new RpcException(method + ": " + e.getMessage(), e);
        }

        String text = resp.body();
        JsonReader reader = new JsonReader(text);
        Object parsed = reader.readValue();
        if (!(parsed instanceof java.util.Map<?, ?> map)) {
            throw new RpcException(method + ": unexpected response shape: " + text);
        }
        Object err = map.get("error");
        if (err != null && !(err instanceof String s && s.equals("null"))) {
            String msg;
            if (err instanceof java.util.Map<?, ?> em && em.get("message") != null) {
                msg = String.valueOf(em.get("message"));
            } else {
                msg = String.valueOf(err);
            }
            throw new RpcException("RPC " + method + ": " + msg);
        }
        Object result = map.get("result");
        return JsonWriter.write(result);
    }

    public boolean isAvailable() {
        try {
            call("getblockchaininfo");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Returns the current block height via {@code getblockchaininfo.blocks}. */
    public int getBlockCount() {
        String info = call("getblockchaininfo");
        Object parsed = new JsonReader(info).readValue();
        if (parsed instanceof java.util.Map<?, ?> m && m.get("blocks") instanceof Number n) {
            return n.intValue();
        }
        throw new RpcException("getblockchaininfo: missing 'blocks'");
    }

    /** Mines {@code n} blocks. Tries {@code generate} (svnode), falls back to {@code generatetoaddress}. */
    public void mine(int n) {
        if (isTeranode()) {
            // Teranode regtest coinbase wallet for privkey=1 (matches teranode.sh)
            String addr = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r";
            call("generatetoaddress", n, addr);
            return;
        }
        try {
            call("generate", n);
            return;
        } catch (Exception ignored) { /* fall through */ }
        String addrJson = call("getnewaddress");
        String addr = addrJson.replace("\"", "");
        call("generatetoaddress", n, addr);
    }

    /** Ensures the connected node is actually running regtest. Throws on mainnet/testnet. */
    public void ensureRegtest() {
        String info = call("getblockchaininfo");
        Object parsed = new JsonReader(info).readValue();
        if (parsed instanceof java.util.Map<?, ?> m && m.get("chain") instanceof String chain) {
            if (!"regtest".equals(chain)) {
                throw new RpcException("SAFETY: connected to '" + chain
                    + "' chain, not regtest. Refusing to run integration tests.");
            }
            return;
        }
        throw new RpcException("getblockchaininfo: missing 'chain' field");
    }

    /**
     * Ensures enough blocks exist for coinbase maturity. On Teranode we
     * need height &gt;= 10101 (regtest Genesis activation at 10000 + 101
     * for maturity). On SV node we target 501 (Genesis height 1 + 500
     * headroom for parallel tests).
     */
    public void ensureMatureCoinbase() {
        int target = isTeranode() ? 10_101 : 501;
        int current = getBlockCount();
        if (current < target) {
            mine(target - current);
        }
    }

    public static List<String> knownBackends() {
        return List.of("svnode", "teranode");
    }

    private static String encodeParam(Object p) {
        if (p == null) return "null";
        if (p instanceof String s) {
            return "\"" + escapeJson(s) + "\"";
        }
        if (p instanceof Boolean b) return b.toString();
        if (p instanceof Number n) return n.toString();
        if (p instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(encodeParam(list.get(i)));
            }
            sb.append(']');
            return sb.toString();
        }
        throw new IllegalArgumentException("RpcClient: unsupported param type " + p.getClass().getName());
    }

    private static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    /** Thrown when the RPC returns an error or the connection fails. */
    public static final class RpcException extends RuntimeException {
        public RpcException(String msg) { super(msg); }
        public RpcException(String msg, Throwable cause) { super(msg, cause); }
    }
}
