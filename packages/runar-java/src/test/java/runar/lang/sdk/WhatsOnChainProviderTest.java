package runar.lang.sdk;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WhatsOnChainProviderTest {

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

    @Test
    void mainnetUsesMainBaseUrl() {
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet");
        assertEquals("https://api.whatsonchain.com/v1/bsv/main", p.getBaseUrl());
        assertEquals("mainnet", p.getNetwork());
    }

    @Test
    void testnetUsesTestBaseUrl() {
        WhatsOnChainProvider p = new WhatsOnChainProvider("testnet");
        assertEquals("https://api.whatsonchain.com/v1/bsv/test", p.getBaseUrl());
    }

    @Test
    void emptyNetworkDefaultsToMainnet() {
        assertEquals("mainnet", new WhatsOnChainProvider("").getNetwork());
        assertEquals("mainnet", new WhatsOnChainProvider().getNetwork());
    }

    // ------------------------------------------------------------------
    // listUtxos hits /address/{addr}/unspent
    // ------------------------------------------------------------------

    @Test
    void listUtxosParsesWocUnspentArray() {
        FakeTransport t = new FakeTransport().queue(200,
            "[{\"tx_hash\":\"" + "aa".repeat(32) + "\",\"tx_pos\":2,\"value\":12345,\"height\":700000},"
                + "{\"tx_hash\":\"" + "bb".repeat(32) + "\",\"tx_pos\":0,\"value\":1,\"height\":700001}]");
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", t);

        List<UTXO> got = p.listUtxos("1ABC");
        assertEquals(2, got.size());
        assertEquals("aa".repeat(32), got.get(0).txid());
        assertEquals(2, got.get(0).outputIndex());
        assertEquals(12345L, got.get(0).satoshis());
        assertEquals("", got.get(0).scriptHex(), "WoC unspent listing has no script");

        // Request shape.
        FakeTransport.Recorded c = t.calls.get(0);
        assertEquals("GET", c.method());
        assertEquals("https://api.whatsonchain.com/v1/bsv/main/address/1ABC/unspent", c.url());
        assertNull(c.body());
    }

    @Test
    void listUtxosReturnsEmptyOn404() {
        FakeTransport t = new FakeTransport().queue(404, "not found");
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", t);
        assertTrue(p.listUtxos("addr").isEmpty());
    }

    @Test
    void listUtxosWrapsServerErrorInProviderException() {
        FakeTransport t = new FakeTransport().queue(500, "boom");
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", t);
        ProviderException pe = assertThrows(ProviderException.class, () -> p.listUtxos("addr"));
        assertEquals(500, pe.statusCode());
        assertTrue(pe.getMessage().contains("boom"));
    }

    // ------------------------------------------------------------------
    // broadcastRaw POSTs JSON to /tx/raw
    // ------------------------------------------------------------------

    @Test
    void broadcastRawSendsTxHexAndReturnsTxid() {
        FakeTransport t = new FakeTransport().queue(200, "\"" + "cd".repeat(32) + "\"");
        WhatsOnChainProvider p = new WhatsOnChainProvider("testnet", t);

        String txid = p.broadcastRaw("deadbeef");
        assertEquals("cd".repeat(32), txid);

        FakeTransport.Recorded c = t.calls.get(0);
        assertEquals("POST", c.method());
        assertEquals("https://api.whatsonchain.com/v1/bsv/test/tx/raw", c.url());
        assertEquals("application/json", c.headers().get("Content-Type"));
        Map<String, Object> body = Json.asObject(Json.parse(c.body()));
        assertEquals("deadbeef", body.get("txhex"));
    }

    @Test
    void broadcastRawRejectsEmptyHex() {
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", new FakeTransport());
        assertThrows(IllegalArgumentException.class, () -> p.broadcastRaw(""));
        assertThrows(IllegalArgumentException.class, () -> p.broadcastRaw(null));
    }

    @Test
    void broadcastRawSurfacesNon200Errors() {
        FakeTransport t = new FakeTransport().queue(400, "duplicate transaction");
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", t);

        ProviderException pe = assertThrows(ProviderException.class, () -> p.broadcastRaw("dead"));
        assertEquals(400, pe.statusCode());
        assertTrue(pe.getMessage().contains("duplicate"));
    }

    // ------------------------------------------------------------------
    // getUtxo hits /tx/hash/{txid} and indexes vout
    // ------------------------------------------------------------------

    @Test
    void getUtxoExtractsScriptAndSatoshis() {
        String body = "{\"txid\":\"" + "ab".repeat(32) + "\",\"version\":1,"
            + "\"vin\":[],"
            + "\"vout\":["
            + "  {\"value\":0.0001,\"n\":0,\"scriptPubKey\":{\"hex\":\"76a91400\"}},"
            + "  {\"value\":0.5,\"n\":1,\"scriptPubKey\":{\"hex\":\"6a\"}}"
            + "],\"locktime\":0}";
        FakeTransport t = new FakeTransport().queue(200, body);
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", t);

        UTXO u = p.getUtxo("ab".repeat(32), 1);
        assertNotNull(u);
        assertEquals(50_000_000L, u.satoshis());
        assertEquals("6a", u.scriptHex());

        assertEquals("https://api.whatsonchain.com/v1/bsv/main/tx/hash/" + "ab".repeat(32),
            t.calls.get(0).url());
    }

    @Test
    void getUtxoReturnsNullOn404() {
        FakeTransport t = new FakeTransport().queue(404, "");
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", t);
        assertNull(p.getUtxo("ab".repeat(32), 0));
    }

    // ------------------------------------------------------------------
    // getRawTransaction hits /tx/{txid}/hex
    // ------------------------------------------------------------------

    @Test
    void getRawTransactionTrimsResponseBody() {
        FakeTransport t = new FakeTransport().queue(200, "  deadbeef\n");
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", t);

        assertEquals("deadbeef", p.getRawTransaction("ab".repeat(32)));
        assertEquals("https://api.whatsonchain.com/v1/bsv/main/tx/" + "ab".repeat(32) + "/hex",
            t.calls.get(0).url());
    }
}
