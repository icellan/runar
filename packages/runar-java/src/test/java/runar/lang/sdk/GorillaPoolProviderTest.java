package runar.lang.sdk;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GorillaPoolProviderTest {

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
            calls.add(new Recorded(method, url,
                headers == null ? Map.of() : Map.copyOf(headers), body));
            if (queued.isEmpty()) throw new AssertionError("no queued response for " + method + " " + url);
            return queued.remove(0);
        }
    }

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    @Test
    void mainnetUsesProductionApi() {
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet");
        assertEquals("https://ordinals.gorillapool.io/api", p.getBaseUrl());
        assertEquals("mainnet", p.getNetwork());
    }

    @Test
    void testnetUsesTestnetApi() {
        GorillaPoolProvider p = new GorillaPoolProvider("testnet");
        assertEquals("https://testnet.ordinals.gorillapool.io/api", p.getBaseUrl());
    }

    @Test
    void emptyOrNullNetworkDefaultsToMainnet() {
        assertEquals("mainnet", new GorillaPoolProvider("").getNetwork());
        assertEquals("mainnet", new GorillaPoolProvider().getNetwork());
    }

    // ------------------------------------------------------------------
    // listUtxos hits /address/{addr}/utxos and parses txid/vout/satoshis/script
    // ------------------------------------------------------------------

    @Test
    void listUtxosParsesGorillaPoolPayload() {
        FakeTransport t = new FakeTransport().queue(200,
            "[{\"txid\":\"" + "aa".repeat(32) + "\",\"vout\":0,\"satoshis\":12345,\"script\":\"76a914aa\"},"
                + "{\"txid\":\"" + "bb".repeat(32) + "\",\"vout\":3,\"satoshis\":1}]");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);

        List<UTXO> got = p.listUtxos("1ADDR");
        assertEquals(2, got.size());
        assertEquals("aa".repeat(32), got.get(0).txid());
        assertEquals(0, got.get(0).outputIndex());
        assertEquals(12345L, got.get(0).satoshis());
        assertEquals("76a914aa", got.get(0).scriptHex());
        assertEquals("", got.get(1).scriptHex(), "missing script defaults to empty");

        assertEquals("https://ordinals.gorillapool.io/api/address/1ADDR/utxos",
            t.calls.get(0).url());
    }

    @Test
    void listUtxosReturnsEmptyOn404() {
        FakeTransport t = new FakeTransport().queue(404, "");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertTrue(p.listUtxos("addr").isEmpty());
    }

    @Test
    void listUtxosWrapsServerErrorInProviderException() {
        FakeTransport t = new FakeTransport().queue(503, "upstream busy");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        ProviderException pe = assertThrows(ProviderException.class, () -> p.listUtxos("addr"));
        assertEquals(503, pe.statusCode());
        assertTrue(pe.getMessage().contains("upstream busy"));
    }

    // ------------------------------------------------------------------
    // broadcastRaw POSTs {"rawTx":"..."} and tolerates several response shapes
    // ------------------------------------------------------------------

    @Test
    void broadcastRawSendsRawTxFieldAndAcceptsJsonStringResponse() {
        FakeTransport t = new FakeTransport().queue(200, "\"" + "cd".repeat(32) + "\"");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);

        String txid = p.broadcastRaw("deadbeef");
        assertEquals("cd".repeat(32), txid);

        FakeTransport.Recorded c = t.calls.get(0);
        assertEquals("POST", c.method());
        assertEquals("https://ordinals.gorillapool.io/api/tx", c.url());
        assertEquals("application/json", c.headers().get("Content-Type"));
        Map<String, Object> body = Json.asObject(Json.parse(c.body()));
        assertEquals("deadbeef", body.get("rawTx"));
    }

    @Test
    void broadcastRawAcceptsTxidEnvelope() {
        FakeTransport t = new FakeTransport().queue(200,
            "{\"txid\":\"" + "11".repeat(32) + "\",\"status\":\"ok\"}");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("11".repeat(32), p.broadcastRaw("aa"));
    }

    @Test
    void broadcastRawFallsBackToPlainTextBody() {
        FakeTransport t = new FakeTransport().queue(200, "ee".repeat(32));
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("ee".repeat(32), p.broadcastRaw("aa"));
    }

    @Test
    void broadcastRawSurfacesNon200Errors() {
        FakeTransport t = new FakeTransport().queue(400, "bad tx");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        ProviderException pe = assertThrows(ProviderException.class, () -> p.broadcastRaw("aa"));
        assertEquals(400, pe.statusCode());
        assertTrue(pe.getMessage().contains("bad tx"));
    }

    // ------------------------------------------------------------------
    // getUtxo hits /tx/{txid}
    // ------------------------------------------------------------------

    @Test
    void getUtxoIndexesVoutAndExtractsScript() {
        String body = "{\"txid\":\"" + "ab".repeat(32) + "\",\"version\":1,\"vin\":[],"
            + "\"vout\":["
            + "  {\"value\":1000000,\"n\":0,\"scriptPubKey\":{\"hex\":\"76a91400\"}},"
            + "  {\"value\":42,\"n\":1,\"scriptPubKey\":{\"hex\":\"6a\"}}"
            + "],\"locktime\":0}";
        FakeTransport t = new FakeTransport().queue(200, body);
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);

        UTXO u = p.getUtxo("ab".repeat(32), 0);
        assertNotNull(u);
        assertEquals(1_000_000L, u.satoshis(), "value >= 1000 is treated as raw satoshis");
        assertEquals("76a91400", u.scriptHex());

        assertEquals("https://ordinals.gorillapool.io/api/tx/" + "ab".repeat(32),
            t.calls.get(0).url());
    }

    @Test
    void getUtxoReturnsNullOn404() {
        FakeTransport t = new FakeTransport().queue(404, "");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertNull(p.getUtxo("ab".repeat(32), 0));
    }

    // ------------------------------------------------------------------
    // getRawTransaction
    // ------------------------------------------------------------------

    @Test
    void getRawTransactionTrimsBody() {
        FakeTransport t = new FakeTransport().queue(200, " deadbeef \n");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("deadbeef", p.getRawTransaction("ab".repeat(32)));
        assertEquals("https://ordinals.gorillapool.io/api/tx/" + "ab".repeat(32) + "/hex",
            t.calls.get(0).url());
    }

    // ------------------------------------------------------------------
    // Token helpers
    // ------------------------------------------------------------------

    @Test
    void getBSV20BalanceParsesStringResponse() {
        FakeTransport t = new FakeTransport().queue(200, "\"123456\"");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("123456", p.getBSV20Balance("1ADDR", "DOGE"));
        assertTrue(t.calls.get(0).url().endsWith("/bsv20/balance/1ADDR/DOGE"));
    }

    @Test
    void getBSV20BalanceParsesObjectResponse() {
        FakeTransport t = new FakeTransport().queue(200, "{\"balance\":\"7\"}");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("7", p.getBSV20Balance("a", "TICK"));
    }

    @Test
    void getBSV20BalanceReturnsZeroOn404() {
        FakeTransport t = new FakeTransport().queue(404, "");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("0", p.getBSV20Balance("a", "TICK"));
    }

    @Test
    void getBSV21UtxosUrlEncodesId() {
        FakeTransport t = new FakeTransport().queue(200, "[]");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        p.getBSV21Utxos("1ADDR", "abcd_0");
        assertTrue(t.calls.get(0).url().endsWith("/bsv20/utxos/1ADDR/abcd_0"),
            t.calls.get(0).url());
    }

    // ------------------------------------------------------------------
    // Contract UTXO helper
    // ------------------------------------------------------------------

    @Test
    void getContractUtxosHitsScriptEndpoint() {
        FakeTransport t = new FakeTransport().queue(200,
            "[{\"txid\":\"" + "aa".repeat(32) + "\",\"vout\":0,\"satoshis\":1,\"script\":\"\"}]");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        List<UTXO> got = p.getContractUtxos("ff".repeat(32));
        assertEquals(1, got.size());
        assertEquals("https://ordinals.gorillapool.io/api/script/" + "ff".repeat(32) + "/utxos",
            t.calls.get(0).url());
    }

    @Test
    void getContractUtxosReturnsEmptyOn404() {
        FakeTransport t = new FakeTransport().queue(404, "");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertTrue(p.getContractUtxos("ff".repeat(32)).isEmpty());
    }
}
