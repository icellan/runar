package runar.lang.sdk;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RPCProviderTest {

    /** Records each outgoing call and replies with a queued canned response. */
    private static final class FakeTransport implements HttpTransport {
        final List<Recorded> calls = new ArrayList<>();
        final List<Response> queued = new ArrayList<>();

        record Recorded(String method, String url, Map<String, String> headers, String body) {}

        FakeTransport queue(int code, String body) {
            queued.add(new Response(code, body));
            return this;
        }

        @Override
        public Response send(String method, String url, Map<String, String> headers, String body) {
            calls.add(new Recorded(method, url, headers == null ? Map.of() : Map.copyOf(headers), body));
            if (queued.isEmpty()) throw new AssertionError("FakeTransport: no canned response queued for " + method + " " + url);
            return queued.remove(0);
        }
    }

    private static String rpcOk(String resultJson) {
        return "{\"result\":" + resultJson + ",\"error\":null,\"id\":\"runar-1\"}";
    }

    private static String rpcErr(int code, String message) {
        return "{\"result\":null,\"error\":{\"code\":" + code + ",\"message\":\"" + message + "\"},\"id\":\"runar-1\"}";
    }

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    @Test
    void defaultsToTestnetWithoutAutoMine() {
        RPCProvider p = new RPCProvider("http://localhost:18332", "u", "p");
        assertEquals("testnet", p.getNetwork());
        assertFalse(p.isAutoMine());
    }

    @Test
    void regtestFactoryFlipsNetworkAndAutoMine() {
        RPCProvider p = RPCProvider.regtest("http://localhost:18443", "u", "p");
        assertEquals("regtest", p.getNetwork());
        assertTrue(p.isAutoMine());
    }

    @Test
    void rejectsNullCredentials() {
        assertThrows(IllegalArgumentException.class,
            () -> new RPCProvider(null, "u", "p"));
        assertThrows(IllegalArgumentException.class,
            () -> new RPCProvider("http://x", null, "p"));
        assertThrows(IllegalArgumentException.class,
            () -> new RPCProvider("http://x", "u", null));
    }

    // ------------------------------------------------------------------
    // listunspent → listUtxos
    // ------------------------------------------------------------------

    @Test
    void listUtxosBuildsCorrectRequestAndDecodesAmount() {
        FakeTransport t = new FakeTransport().queue(200, rpcOk(
            "[{\"txid\":\"" + "aa".repeat(32) + "\",\"vout\":0,\"amount\":0.0001,"
                + "\"scriptPubKey\":\"76a914" + "00".repeat(20) + "88ac\"}]"));
        RPCProvider p = new RPCProvider("http://node:8332", "alice", "secret",
            "testnet", false, t);

        List<UTXO> got = p.listUtxos("addrA");
        assertEquals(1, got.size());
        assertEquals("aa".repeat(32), got.get(0).txid());
        assertEquals(0, got.get(0).outputIndex());
        assertEquals(10_000L, got.get(0).satoshis(), "0.0001 BTC = 10_000 sat");

        // Outgoing request shape.
        assertEquals(1, t.calls.size());
        FakeTransport.Recorded c = t.calls.get(0);
        assertEquals("POST", c.method());
        assertEquals("http://node:8332", c.url());
        assertEquals("application/json", c.headers().get("Content-Type"));
        String expectedAuth = "Basic " + Base64.getEncoder().encodeToString("alice:secret".getBytes());
        assertEquals(expectedAuth, c.headers().get("Authorization"));

        Map<String, Object> req = Json.asObject(Json.parse(c.body()));
        assertEquals("listunspent", req.get("method"));
        assertEquals("1.0", req.get("jsonrpc"));
        List<Object> params = Json.asArray(req.get("params"));
        assertEquals(3, params.size());
        assertEquals(0L, Json.asLong(params.get(0)));
        assertEquals(9_999_999L, Json.asLong(params.get(1)));
        List<Object> addrs = Json.asArray(params.get(2));
        assertEquals("addrA", Json.asString(addrs.get(0)));
    }

    @Test
    void listUtxosSurfacesRpcErrorEnvelope() {
        FakeTransport t = new FakeTransport().queue(200, rpcErr(-32601, "Method not found"));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);

        ProviderException pe = assertThrows(ProviderException.class, () -> p.listUtxos("x"));
        assertTrue(pe.getMessage().contains("Method not found"), pe.getMessage());
        assertTrue(pe.getMessage().contains("-32601"));
    }

    @Test
    void listUtxosWraps500WithJsonRpcErrorBody() {
        FakeTransport t = new FakeTransport().queue(500, rpcErr(-1, "node restarting"));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);

        ProviderException pe = assertThrows(ProviderException.class, () -> p.listUtxos("x"));
        assertEquals(500, pe.statusCode());
        assertTrue(pe.getMessage().contains("node restarting"), pe.getMessage());
    }

    // ------------------------------------------------------------------
    // sendrawtransaction → broadcastRaw
    // ------------------------------------------------------------------

    @Test
    void broadcastRawReturnsTxidAndPostsRawHex() {
        FakeTransport t = new FakeTransport().queue(200, rpcOk("\"" + "cd".repeat(32) + "\""));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);

        String txid = p.broadcastRaw("deadbeef");
        assertEquals("cd".repeat(32), txid);

        Map<String, Object> req = Json.asObject(Json.parse(t.calls.get(0).body()));
        assertEquals("sendrawtransaction", req.get("method"));
        List<Object> params = Json.asArray(req.get("params"));
        assertEquals(1, params.size());
        assertEquals("deadbeef", Json.asString(params.get(0)));
    }

    @Test
    void broadcastRawRejectsEmptyHex() {
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false,
            new FakeTransport());
        assertThrows(IllegalArgumentException.class, () -> p.broadcastRaw(""));
        assertThrows(IllegalArgumentException.class, () -> p.broadcastRaw(null));
    }

    @Test
    void broadcastRawAutoMinesAfterSuccessOnRegtest() {
        FakeTransport t = new FakeTransport()
            .queue(200, rpcOk("\"" + "cd".repeat(32) + "\""))   // sendrawtransaction
            .queue(200, rpcOk("[\"00\"]"));                      // generate
        RPCProvider p = new RPCProvider("http://node", "u", "p", "regtest", true, t);

        String txid = p.broadcastRaw("aabb");
        assertEquals("cd".repeat(32), txid);
        assertEquals(2, t.calls.size(), "broadcast + generate");
        Map<String, Object> mineReq = Json.asObject(Json.parse(t.calls.get(1).body()));
        assertEquals("generate", mineReq.get("method"));
        assertEquals(1L, Json.asLong(Json.asArray(mineReq.get("params")).get(0)));
    }

    // ------------------------------------------------------------------
    // getrawtransaction → getUtxo
    // ------------------------------------------------------------------

    @Test
    void getUtxoExtractsScriptPubKeyAndSatoshis() {
        String tx = "{\"hex\":\"deadbeef\",\"vout\":["
            + "{\"value\":0.00012345,\"n\":0,\"scriptPubKey\":{\"hex\":\"76a91400\"}},"
            + "{\"value\":0.5,\"n\":1,\"scriptPubKey\":{\"hex\":\"6a\"}}"
            + "]}";
        FakeTransport t = new FakeTransport().queue(200, rpcOk(tx));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);

        UTXO u = p.getUtxo("ab".repeat(32), 1);
        assertNotNull(u);
        assertEquals("ab".repeat(32), u.txid());
        assertEquals(1, u.outputIndex());
        assertEquals(50_000_000L, u.satoshis());
        assertEquals("6a", u.scriptHex());
    }

    @Test
    void getUtxoReturnsNullWhenNodeReportsNotFound() {
        FakeTransport t = new FakeTransport().queue(200, rpcErr(-5, "No such mempool or blockchain transaction"));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);

        assertNull(p.getUtxo("00".repeat(32), 0));
    }

    @Test
    void getUtxoOutOfRangeVoutReturnsNull() {
        String tx = "{\"hex\":\"\",\"vout\":[{\"value\":0.001,\"n\":0,\"scriptPubKey\":{\"hex\":\"\"}}]}";
        FakeTransport t = new FakeTransport().queue(200, rpcOk(tx));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);

        assertNull(p.getUtxo("ab".repeat(32), 5));
    }

    // ------------------------------------------------------------------
    // getRawTransaction (non-verbose) helper
    // ------------------------------------------------------------------

    @Test
    void getRawTransactionReturnsHexString() {
        FakeTransport t = new FakeTransport().queue(200, rpcOk("\"deadbeef\""));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);
        assertEquals("deadbeef", p.getRawTransaction("ab".repeat(32)));

        Map<String, Object> req = Json.asObject(Json.parse(t.calls.get(0).body()));
        List<Object> params = Json.asArray(req.get("params"));
        assertEquals(0L, Json.asLong(params.get(1)), "verbose flag must be 0");
    }

    // ------------------------------------------------------------------
    // Request envelope shape
    // ------------------------------------------------------------------

    @Test
    void rpcRequestEnvelopeIncludesIncrementingId() {
        FakeTransport t = new FakeTransport()
            .queue(200, rpcOk("[]"))
            .queue(200, rpcOk("[]"));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);
        p.listUtxos("a");
        p.listUtxos("b");

        Map<String, Object> r1 = Json.asObject(Json.parse(t.calls.get(0).body()));
        Map<String, Object> r2 = Json.asObject(Json.parse(t.calls.get(1).body()));
        assertEquals("runar-1", r1.get("id"));
        assertEquals("runar-2", r2.get("id"));
    }

    // ------------------------------------------------------------------
    // Encoder direct check (sanity for the bespoke JsonWriter path)
    // ------------------------------------------------------------------

    @Test
    void encodeRpcRequestProducesParseableJson() {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("v", 1L);
        req.put("s", "with \"quotes\"");
        String body = JsonWriter.write(req);
        Map<String, Object> back = Json.asObject(Json.parse(body));
        assertEquals(1L, Json.asLong(back.get("v")));
        assertEquals("with \"quotes\"", back.get("s"));
    }
}
