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
    void emptyOrNullNetworkIsRejectedNotDefaultedToMainnet() {
        // R-051: an unparseable network is a programming error, not a default.
        assertThrows(IllegalArgumentException.class, () -> new WhatsOnChainProvider(""));
        assertThrows(IllegalArgumentException.class, () -> new WhatsOnChainProvider((String) null));
        assertThrows(IllegalArgumentException.class, () -> new WhatsOnChainProvider("mainnett"));
        // The no-arg constructor still selects mainnet — that is an explicit
        // choice at the call site, not an unvalidated string.
        assertEquals("mainnet", new WhatsOnChainProvider().getNetwork());
    }

    // ------------------------------------------------------------------
    // listUtxos hits /address/{addr}/unspent
    // ------------------------------------------------------------------

    // F-040: this test used to assert the empty script as "WoC unspent listing
    // has no script". That empty script became the BIP-143 scriptCode of every
    // funding signature. listUtxos now also fetches /tx/{txid}/hex per UTXO, so
    // the test replays the recorded listing + raw txs (conformance/sdk-woc).
    @Test
    @SuppressWarnings("unchecked")
    void listUtxosParsesWocUnspentArray() throws Exception {
        java.nio.file.Path vp = java.nio.file.Paths.get(System.getProperty("user.dir"),
            "..", "..", "conformance", "sdk-woc", "vectors.json");
        Map<String, Object> v = (Map<String, Object>) Json.parse(java.nio.file.Files.readString(vp));
        Map<String, Object> raw = (Map<String, Object>) v.get("rawTxHex");
        List<Map<String, Object>> expected = (List<Map<String, Object>>) v.get("expected");
        String address = (String) v.get("address");
        FakeTransport t = new FakeTransport()
            .queue(200, (String) v.get("unspentBody"))
            .queue(200, (String) raw.get(expected.get(0).get("txid")))
            .queue(200, (String) raw.get(expected.get(1).get("txid")));
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", t);

        List<UTXO> got = p.listUtxos(address);
        assertEquals(2, got.size());
        assertEquals(expected.get(0).get("txid"), got.get(0).txid());
        assertEquals(1, got.get(0).outputIndex());
        assertEquals(29884L, got.get(0).satoshis());
        assertEquals(expected.get(0).get("script"), got.get(0).scriptHex());

        // Request shape.
        FakeTransport.Recorded c = t.calls.get(0);
        assertEquals("GET", c.method());
        assertEquals("https://api.whatsonchain.com/v1/bsv/main/address/" + address + "/unspent", c.url());
        assertNull(c.body());
        assertEquals("https://api.whatsonchain.com/v1/bsv/main/tx/" + expected.get(0).get("txid") + "/hex",
            t.calls.get(1).url());
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
