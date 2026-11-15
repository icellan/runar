package runar.integration;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import runar.integration.helpers.NodeRejection;
import runar.integration.helpers.RpcClient;
import runar.integration.helpers.RpcProvider;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Node-free tests for {@link NodeRejection}, driven through the real
 * {@link RpcProvider#broadcastRaw} against a stub JSON-RPC server on
 * 127.0.0.1. Ungated, like {@link RpcHelperSafetyTest}.
 *
 * <p>R2-NEGATIVES: after GK-BUG-004 an ACCEPTED transaction whose confirming
 * mine fails makes broadcastRaw throw after an attempt, so the old negative
 * pattern ({@code assertThrows} plus a moved attempt counter) passed on an
 * accepted spend. The first test is that case.
 */
class NodeRejectionTest {

    private static final String TXID = "ab".repeat(32);
    private static final Pattern METHOD = Pattern.compile("\"method\":\"([^\"]+)\"");
    private static final String SCRIPT_FAILURE =
        "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)";

    private HttpServer server;

    private String stubNode(Function<String, String> answer) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            String body;
            try (InputStream in = ex.getRequestBody()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            Matcher m = METHOD.matcher(body);
            byte[] out = answer.apply(m.find() ? m.group(1) : "").getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static String ok(String resultJson) {
        return "{\"result\":" + resultJson + ",\"error\":null,\"id\":1}";
    }

    private static String rpcError(int code, String msg) {
        return "{\"result\":null,\"error\":{\"code\":" + code + ",\"message\":\"" + msg + "\"},\"id\":1}";
    }

    private RpcProvider provider(Function<String, String> answer) throws IOException {
        return new RpcProvider(new RpcClient(stubNode(answer), "u", "p", "svnode"));
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    @DisplayName("an ACCEPTED tx whose confirming mine failed is not a rejection")
    void acceptedThenMineFailedIsNotARejection() throws IOException {
        RpcProvider p = provider(method -> method.equals("sendrawtransaction")
            ? ok("\"" + TXID + "\"") : rpcError(-32601, "Method not found"));
        AssertionFailedError e = assertThrows(AssertionFailedError.class,
            () -> NodeRejection.assertNodeRejected(p, () -> p.broadcastRaw("00"), NodeRejection.SCRIPT_VERIFY_FAILED));
        assertTrue(e.getMessage().contains("ACCEPTED"), e.getMessage());
    }

    @Test
    @DisplayName("a genuine script-verify rejection passes")
    void genuineScriptRejectionPasses() throws IOException {
        RpcProvider p = provider(method -> rpcError(-26, SCRIPT_FAILURE));
        RuntimeException e = NodeRejection.assertNodeRejected(p, () -> p.broadcastRaw("00"),
            NodeRejection.SCRIPT_VERIFY_FAILED);
        assertTrue(e.getMessage().contains(SCRIPT_FAILURE), e.getMessage());
    }

    @Test
    @DisplayName("a node rejection for another reason is refused")
    void wrongReasonIsRefused() throws IOException {
        RpcProvider p = provider(method -> rpcError(-25, "Missing inputs"));
        AssertionFailedError e = assertThrows(AssertionFailedError.class,
            () -> NodeRejection.assertNodeRejected(p, () -> p.broadcastRaw("00"), NodeRejection.SCRIPT_VERIFY_FAILED));
        assertTrue(e.getMessage().contains("wrong reason"), e.getMessage());
    }

    @Test
    @DisplayName("an SDK-side failure (nothing broadcast) is not a rejection")
    void sdkSideFailureIsNotARejection() throws IOException {
        RpcProvider p = provider(method -> rpcError(-26, SCRIPT_FAILURE));
        AssertionFailedError e = assertThrows(AssertionFailedError.class,
            () -> NodeRejection.assertNodeRejected(p, () -> {
                throw new IllegalStateException("fetching utxos: boom");
            }, NodeRejection.SCRIPT_VERIFY_FAILED));
        assertTrue(e.getMessage().contains("never handed a transaction"), e.getMessage());
    }

    @Test
    @DisplayName("a transport failure is not a rejection")
    void transportFailureIsNotARejection() throws IOException {
        int deadPort;
        try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
            deadPort = s.getLocalPort();
        }
        RpcProvider p = new RpcProvider(new RpcClient("http://127.0.0.1:" + deadPort, "u", "p", "svnode"));
        AssertionFailedError e = assertThrows(AssertionFailedError.class,
            () -> NodeRejection.assertNodeRejected(p, () -> p.broadcastRaw("00"), NodeRejection.SCRIPT_VERIFY_FAILED));
        assertTrue(e.getMessage().contains("never ruled"), e.getMessage());
    }
}
