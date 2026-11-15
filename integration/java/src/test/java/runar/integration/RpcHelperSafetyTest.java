package runar.integration;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RpcClient;
import runar.integration.helpers.RpcProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Node-free tests for the integration helpers, driven against a stub JSON-RPC
 * server on 127.0.0.1. Ungated (like {@link WiringSmokeTest}) so a plain
 * {@code gradle test} runs them.
 *
 * <ul>
 *   <li>GK-BUG-004: {@link RpcProvider#broadcastRaw} swallowed a failed
 *       auto-mine ({@code catch (Exception ignored)}) and returned the txid as
 *       if the transaction had been confirmed.</li>
 *   <li>GK-BUG-003: on Teranode, {@link IntegrationWallet#createFunded}
 *       returned an UNFUNDED wallet; {@link RpcProvider#listUtxos} turned every
 *       transport error into an empty list; and the coinbase-maturity target
 *       was 10,101 while {@code teranode.sh} (Chronicle at 15,000) uses
 *       15,101. Java on Teranode now fails closed — Teranode integration is
 *       Go-only.</li>
 * </ul>
 */
class RpcHelperSafetyTest {

    private static final String TXID = "ab".repeat(32);
    private static final Pattern METHOD = Pattern.compile("\"method\":\"([^\"]+)\"");

    private HttpServer server;
    private final List<String> requests = new CopyOnWriteArrayList<>();

    /** Starts a stub node; {@code answer} maps a raw request body to a raw response body. */
    private String stubNode(Function<String, String> answer) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            String body;
            try (InputStream in = ex.getRequestBody()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            requests.add(body);
            byte[] out = answer.apply(body).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static String method(String body) {
        Matcher m = METHOD.matcher(body);
        return m.find() ? m.group(1) : "";
    }

    private static String ok(String resultJson) {
        return "{\"result\":" + resultJson + ",\"error\":null,\"id\":1}";
    }

    private static String rpcError(String msg) {
        return "{\"result\":null,\"error\":{\"code\":-32601,\"message\":\"" + msg + "\"},\"id\":1}";
    }

    private List<String> methodsSeen() {
        return requests.stream().map(RpcHelperSafetyTest::method).toList();
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    @DisplayName("GK-BUG-004: broadcastRaw throws, with the txid, when the auto-mine fails")
    void broadcastRawPropagatesAutoMineFailure() throws IOException {
        String url = stubNode(body -> switch (method(body)) {
            case "sendrawtransaction" -> ok("\"" + TXID + "\"");
            default -> rpcError("Method not found");
        });
        RpcProvider provider = new RpcProvider(new RpcClient(url, "u", "p", "svnode"));

        RuntimeException e = assertThrows(RuntimeException.class, () -> provider.broadcastRaw("00"),
            "broadcastRaw returned normally although the confirming mine failed");
        assertTrue(e.getMessage().contains(TXID), "message must carry the broadcast txid: " + e.getMessage());
        assertTrue(e.getMessage().contains("auto-mine failed"), "message must name the step: " + e.getMessage());
        assertEquals(1, provider.broadcastAttempts());
        assertTrue(methodsSeen().contains("generate"), "auto-mine never attempted: " + methodsSeen());
    }

    @Test
    @DisplayName("GK-BUG-004 control: broadcastRaw returns the txid when the auto-mine succeeds")
    void broadcastRawReturnsTxidWhenMined() throws IOException {
        String url = stubNode(body -> switch (method(body)) {
            case "sendrawtransaction" -> ok("\"" + TXID + "\"");
            case "generate" -> ok("[\"" + "cd".repeat(32) + "\"]");
            default -> rpcError("unexpected");
        });
        RpcProvider provider = new RpcProvider(new RpcClient(url, "u", "p", "svnode"));
        assertEquals(TXID, provider.broadcastRaw("00"));
    }

    @Test
    @DisplayName("GK-BUG-003: createFunded refuses Teranode instead of returning an unfunded wallet")
    void createFundedFailsClosedOnTeranode() throws IOException {
        String url = stubNode(body -> ok("null"));
        RpcClient rpc = new RpcClient(url, "u", "p", "teranode");
        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> IntegrationWallet.createFunded(rpc, 1.0));
        assertTrue(e.getMessage().contains("Go-only"), "message should point at the Go suite: " + e.getMessage());
        assertFalse(methodsSeen().contains("sendtoaddress"));
    }

    @Test
    @DisplayName("GK-BUG-003: Teranode coinbase-maturity target is 15,101 (Chronicle at 15,000), matching teranode.sh")
    void teranodeMaturityTargetMatchesTeranodeSh() throws IOException {
        String url = stubNode(body -> switch (method(body)) {
            case "getblockchaininfo" -> ok("{\"chain\":\"regtest\",\"blocks\":0}");
            case "generatetoaddress" -> ok("[]");
            default -> rpcError("unexpected " + method(body));
        });
        new RpcClient(url, "u", "p", "teranode").ensureMatureCoinbase();
        String gen = requests.stream().filter(b -> method(b).equals("generatetoaddress")).findFirst()
            .orElseThrow(() -> new AssertionError("no generatetoaddress call: " + methodsSeen()));
        assertTrue(gen.contains("\"params\":[15101,"), "expected 15101 blocks mined, request was: " + gen);
    }

    @Test
    @DisplayName("GK-BUG-003: listUtxos rethrows a transport error instead of reporting no UTXOs")
    void listUtxosRethrowsTransportError() throws IOException {
        int deadPort;
        try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
            deadPort = s.getLocalPort();
        }
        RpcProvider provider = new RpcProvider(
            new RpcClient("http://127.0.0.1:" + deadPort, "u", "p", "svnode"));
        assertThrows(RuntimeException.class, () -> provider.listUtxos("mxyz"),
            "listUtxos returned (an empty list) although the node was unreachable");
    }
}
