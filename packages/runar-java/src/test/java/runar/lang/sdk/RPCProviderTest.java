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

    // ------------------------------------------------------------------
    // Realistic bitcoind / Teranode response shapes
    //
    // These tests use payloads byte-for-byte matching what real bitcoind
    // and Teranode nodes return — extra fields, deeper nesting, scriptPubKey
    // as an object (not just a hex string) — to guard against regressions
    // in the parser when fed real-world data.
    // ------------------------------------------------------------------

    @Test
    void listUtxosToleratesFullBitcoindListunspentShape() {
        // Full bitcoind 0.21+ listunspent response: includes label, confirmations,
        // spendable, solvable, desc, safe, plus the "address" field. The provider
        // must extract only the fields it cares about.
        String body = rpcOk("["
            + "{"
            + "\"txid\":\"" + "aa".repeat(32) + "\","
            + "\"vout\":1,"
            + "\"address\":\"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\","
            + "\"label\":\"\","
            + "\"scriptPubKey\":\"76a914751e76e8199196d454941c45d1b3a323f1433bd688ac\","
            + "\"amount\":0.001,"
            + "\"confirmations\":42,"
            + "\"spendable\":true,"
            + "\"solvable\":true,"
            + "\"desc\":\"pkh([abcdef])#xxxxxxxx\","
            + "\"safe\":true"
            + "}"
            + "]");
        FakeTransport t = new FakeTransport().queue(200, body);
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);
        List<UTXO> got = p.listUtxos("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assertEquals(1, got.size());
        assertEquals(1, got.get(0).outputIndex());
        assertEquals(100_000L, got.get(0).satoshis());
        assertEquals("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", got.get(0).scriptHex());
    }

    @Test
    void listUtxosOrderingPreservedAcrossMultipleEntries() {
        String body = rpcOk("["
            + "{\"txid\":\"" + "11".repeat(32) + "\",\"vout\":0,\"amount\":0.0001,\"scriptPubKey\":\"00\"},"
            + "{\"txid\":\"" + "22".repeat(32) + "\",\"vout\":2,\"amount\":0.0002,\"scriptPubKey\":\"00\"},"
            + "{\"txid\":\"" + "33".repeat(32) + "\",\"vout\":7,\"amount\":0.0003,\"scriptPubKey\":\"00\"}"
            + "]");
        FakeTransport t = new FakeTransport().queue(200, body);
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);
        List<UTXO> got = p.listUtxos("addr");
        assertEquals(3, got.size());
        assertEquals("11".repeat(32), got.get(0).txid());
        assertEquals("22".repeat(32), got.get(1).txid());
        assertEquals("33".repeat(32), got.get(2).txid());
        assertEquals(10_000L, got.get(0).satoshis());
        assertEquals(20_000L, got.get(1).satoshis());
        assertEquals(30_000L, got.get(2).satoshis());
    }

    @Test
    void getUtxoToleratesBitcoindVoutNestedScriptPubKeyShape() {
        // Real bitcoind getrawtransaction (verbose=1) returns scriptPubKey as
        // an OBJECT containing asm, hex, reqSigs, type, addresses[]. Our
        // existing happy-path test uses a simpler shape; here's the full one.
        String body = rpcOk("{"
            + "\"in_active_chain\":true,"
            + "\"txid\":\"" + "ab".repeat(32) + "\","
            + "\"hash\":\"" + "ab".repeat(32) + "\","
            + "\"version\":1,"
            + "\"size\":109,"
            + "\"locktime\":0,"
            + "\"vin\":[],"
            + "\"vout\":["
            + "  {"
            + "    \"value\":0.00012345,"
            + "    \"n\":0,"
            + "    \"scriptPubKey\":{"
            + "      \"asm\":\"OP_DUP OP_HASH160 751e76e8199196d454941c45d1b3a323f1433bd6 OP_EQUALVERIFY OP_CHECKSIG\","
            + "      \"hex\":\"76a914751e76e8199196d454941c45d1b3a323f1433bd688ac\","
            + "      \"reqSigs\":1,"
            + "      \"type\":\"pubkeyhash\","
            + "      \"addresses\":[\"1Bitcoin\"]"
            + "    }"
            + "  }"
            + "],"
            + "\"blockhash\":\"" + "cd".repeat(32) + "\","
            + "\"confirmations\":1,"
            + "\"time\":1735689600,"
            + "\"blocktime\":1735689600,"
            + "\"hex\":\"deadbeef\""
            + "}");
        FakeTransport t = new FakeTransport().queue(200, body);
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);
        UTXO u = p.getUtxo("ab".repeat(32), 0);
        assertNotNull(u);
        assertEquals(12_345L, u.satoshis());
        assertEquals("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", u.scriptHex());
    }

    @Test
    void broadcastRawHandlesTeranodeAlreadyKnownTransactionError() {
        // Teranode (and bitcoind) return -27 ("transaction already in block chain")
        // for re-broadcast of a confirmed tx. Provider must surface this as a
        // ProviderException, not silently succeed.
        FakeTransport t = new FakeTransport().queue(200,
            rpcErr(-27, "transaction already in block chain"));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);
        ProviderException ex = assertThrows(ProviderException.class, () -> p.broadcastRaw("aabb"));
        assertTrue(ex.getMessage().contains("-27"), ex.getMessage());
        assertTrue(ex.getMessage().contains("already in block chain"), ex.getMessage());
    }

    @Test
    void broadcastRawHandlesMempoolPolicyRejection() {
        // Real bitcoind returns -26 with reason: "min relay fee not met" or
        // similar policy errors. Provider must propagate the message.
        FakeTransport t = new FakeTransport().queue(200,
            rpcErr(-26, "min relay fee not met, 0 < 250"));
        RPCProvider p = new RPCProvider("http://node", "u", "p", "testnet", false, t);
        ProviderException ex = assertThrows(ProviderException.class, () -> p.broadcastRaw("aabb"));
        assertTrue(ex.getMessage().contains("min relay fee not met"), ex.getMessage());
    }
}
