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

import runar.integration.helpers.RpcClient;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.UTXO;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Node-free tests for {@link RpcProvider#getUtxo}, against a stub JSON-RPC
 * server on 127.0.0.1. Ungated, like {@link NodeRejectionTest}.
 *
 * <p>R3-JAVA-GETUTXO: getUtxo caught every exception and returned null, so an
 * unreachable node, a node-side RPC failure or a malformed reply all read as
 * "this outpoint does not exist". Only the node's own not-found answer
 * (JSON-RPC code -5, "No such mempool or blockchain transaction") may be
 * empty; everything else propagates.
 */
class RpcProviderGetUtxoTest {

    private static final String TXID = "cd".repeat(32);
    private static final Pattern METHOD = Pattern.compile("\"method\":\"([^\"]+)\"");
    private static final String SCRIPT = "76a914" + "00".repeat(20) + "88ac";

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
            // SV Node answers a JSON-RPC error with HTTP 500 and the error in the body.
            ex.sendResponseHeaders(new String(out, StandardCharsets.UTF_8).contains("\"error\":{") ? 500 : 200, out.length);
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

    private static String verboseTx() {
        return "{\"txid\":\"" + TXID + "\",\"vout\":[{\"value\":0.0001,\"n\":0,\"scriptPubKey\":{\"hex\":\"" + SCRIPT + "\"}}]}";
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    @DisplayName("an unreachable node is an error, not a missing outpoint")
    void transportFailurePropagates() throws IOException {
        int closedPort;
        try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            closedPort = s.getLocalPort();
        }
        RpcProvider p = new RpcProvider(new RpcClient("http://127.0.0.1:" + closedPort, "u", "p", "svnode"));
        RpcClient.RpcException e = assertThrows(RpcClient.RpcException.class, () -> p.getUtxo(TXID, 0));
        assertTrue(e.getMessage().startsWith("getrawtransaction: "), e.getMessage());
        assertNull(e.rpcCode());
    }

    @Test
    @DisplayName("a node-side RPC failure other than not-found propagates with its code")
    void rpcErrorPropagates() throws IOException {
        RpcProvider p = provider(m -> rpcError(-28, "Loading block index..."));
        RpcClient.RpcException e = assertThrows(RpcClient.RpcException.class, () -> p.getUtxo(TXID, 0));
        assertEquals(Integer.valueOf(-28), e.rpcCode());
        assertTrue(e.getMessage().contains("Loading block index"), e.getMessage());
    }

    @Test
    @DisplayName("a malformed getrawtransaction reply is an error")
    void malformedReplyPropagates() throws IOException {
        RpcProvider p = provider(m -> ok("\"not-a-verbose-object\""));
        RpcClient.RpcException e = assertThrows(RpcClient.RpcException.class, () -> p.getUtxo(TXID, 0));
        assertTrue(e.getMessage().contains("getrawtransaction"), e.getMessage());
    }

    @Test
    @DisplayName("an output with no scriptPubKey hex is an error")
    void outputWithoutScriptPropagates() throws IOException {
        RpcProvider p = provider(m -> ok("{\"vout\":[{\"value\":0.0001,\"n\":0,\"scriptPubKey\":{}}]}"));
        assertThrows(RpcClient.RpcException.class, () -> p.getUtxo(TXID, 0));
    }

    @Test
    @DisplayName("the node's not-found answer (-5) is the one empty result")
    void notFoundIsNull() throws IOException {
        RpcProvider p = provider(m -> rpcError(-5,
            "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."));
        assertNull(p.getUtxo(TXID, 0));
    }

    @Test
    @DisplayName("an output index past the transaction's outputs is not found")
    void voutOutOfRangeIsNull() throws IOException {
        RpcProvider p = provider(m -> ok(verboseTx()));
        assertNull(p.getUtxo(TXID, 1));
    }

    @Test
    @DisplayName("control: a real output is returned")
    void foundOutput() throws IOException {
        RpcProvider p = provider(m -> ok(verboseTx()));
        UTXO u = p.getUtxo(TXID, 0);
        assertNotNull(u);
        assertEquals(10_000L, u.satoshis());
        assertEquals(SCRIPT, u.scriptHex());
    }
}
