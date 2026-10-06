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
    void emptyOrNullNetworkIsRejectedNotDefaultedToMainnet() {
        // R-051: an unparseable network is a programming error, not a default.
        assertThrows(IllegalArgumentException.class, () -> new GorillaPoolProvider(""));
        assertThrows(IllegalArgumentException.class, () -> new GorillaPoolProvider((String) null));
        assertThrows(IllegalArgumentException.class, () -> new GorillaPoolProvider("mainnett"));
        // The no-arg constructor still selects mainnet — that is an explicit
        // choice at the call site, not an unvalidated string.
        assertEquals("mainnet", new GorillaPoolProvider().getNetwork());
    }

    // ------------------------------------------------------------------
    // listUtxos hits /txos/address/{addr}/unspent (N-025)
    //
    // N-025: replaces listUtxosParsesGorillaPoolPayload / listUtxosReturnsEmptyOn404,
    // which pinned the undocumented /address/{addr}/utxos route (a 404 on the live
    // API) and mapped its 404 to an empty list. The listing has no script, so the
    // script and value now come from the hash-verified raw tx.
    // ------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void listUtxosTakesScriptAndValueFromVerifiedRawTx() throws Exception {
        Map<String, Object> v = ((List<Map<String, Object>>) loadGorillaPoolVectors().get("vectors")).get(0);
        String txid = (String) v.get("txid");
        Map<String, Object> out0 = ((List<Map<String, Object>>)
            ((Map<String, Object>) v.get("expected")).get("outputs")).get(0);
        long sats = Json.asLong(out0.get("satoshis"));
        FakeTransport t = new FakeTransport().queue(200,
            "[{\"txid\":\"" + txid + "\",\"vout\":0,\"satoshis\":" + sats + "}]");
        FakeRawFetcher f = new FakeRawFetcher(rawUrl(txid), ScriptUtils.hexToBytes((String) v.get("responseHex")));
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t, f);

        List<UTXO> got = p.listUtxos("1ADDR");
        assertEquals(1, got.size());
        assertEquals(txid, got.get(0).txid());
        assertEquals(0, got.get(0).outputIndex());
        assertEquals(sats, got.get(0).satoshis());
        assertEquals(out0.get("scriptSha256"), sha256Hex(got.get(0).scriptHex()));
        assertEquals("https://ordinals.gorillapool.io/api/txos/address/1ADDR/unspent", t.calls.get(0).url());
        assertEquals(rawUrl(txid), f.urls.get(0));
    }

    @Test
    void listUtxosReturnsEmptyForEmptyListing() {
        FakeTransport t = new FakeTransport().queue(200, "[]");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertTrue(p.listUtxos("addr").isEmpty());
    }

    @Test
    void listUtxosThrowsOn404() {
        FakeTransport t = new FakeTransport().queue(404, "{\"message\":\"Not Found\"}");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        ProviderException pe = assertThrows(ProviderException.class, () -> p.listUtxos("addr"));
        assertEquals(404, pe.statusCode());
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
    // broadcastRaw POSTs {"rawtx":"..."} (N-025: the documented key) and
    // tolerates several response shapes
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
        // N-025: the documented Broadcast body is {"rawtx": string}; "rawTx" is not accepted.
        assertEquals("deadbeef", body.get("rawtx"));
        assertFalse(body.containsKey("rawTx"));
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
    // getUtxo hits /tx/{txid}/raw (F-027)
    //
    // GorillaPool's GET /tx/{txid} is binary, not the JSON `vout[].value` the
    // old decoder (with its `< 1000 → BTC` guess) expected. getUtxo now fetches
    // /tx/{txid}/raw and reads the output's 8-byte LE satoshis from the raw tx.
    // Proves: every output of the shared recorded vectors
    // (conformance/sdk-gorillapool) decodes exactly — a real 1-sat inscription
    // output is 1 sat; 999/1000/1e12/2.1e15 exact — and a body hashing to
    // another txid is rejected. Does NOT prove the live API still serves
    // /tx/{txid}/raw (recorded 2026-09-27).
    // ------------------------------------------------------------------

    /** Binary fake: serves {@code body} at {@code url}, 404 elsewhere. */
    private static final class FakeRawFetcher implements GorillaPoolProvider.RawFetcher {
        final List<String> urls = new ArrayList<>();
        final String url;
        final byte[] body;

        FakeRawFetcher(String url, byte[] body) {
            this.url = url;
            this.body = body;
        }

        @Override
        public GorillaPoolProvider.RawResponse get(String u) {
            urls.add(u);
            return u.equals(url)
                ? new GorillaPoolProvider.RawResponse(200, body)
                : new GorillaPoolProvider.RawResponse(404, "{\"message\":\"Not Found\"}".getBytes());
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadGorillaPoolVectors() throws Exception {
        java.nio.file.Path p = java.nio.file.Paths.get(System.getProperty("user.dir"),
            "..", "..", "conformance", "sdk-gorillapool", "vectors.json");
        return (Map<String, Object>) Json.parse(java.nio.file.Files.readString(p));
    }

    private static String sha256Hex(String hex) {
        return ScriptUtils.bytesToHex(Hash160.sha256(ScriptUtils.hexToBytes(hex)));
    }

    private static String rawUrl(String txid) {
        return "https://ordinals.gorillapool.io/api/tx/" + txid + "/raw";
    }

    // F-027: replaces getUtxoIndexesVoutAndExtractsScript, which pinned the
    // `value >= 1000 is treated as raw satoshis` heuristic on JSON GorillaPool never returns.
    @Test
    @SuppressWarnings("unchecked")
    void getUtxoDecodesRecordedRawTxVectors() throws Exception {
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) loadGorillaPoolVectors().get("vectors");
        assertTrue(vectors.size() >= 3);
        for (Map<String, Object> v : vectors) {
            String name = (String) v.get("name");
            String txid = (String) v.get("txid");
            FakeRawFetcher f = new FakeRawFetcher(rawUrl(txid),
                ScriptUtils.hexToBytes((String) v.get("responseHex")));
            GorillaPoolProvider p = new GorillaPoolProvider("mainnet", new FakeTransport(), f);
            List<Map<String, Object>> outs = (List<Map<String, Object>>)
                ((Map<String, Object>) v.get("expected")).get("outputs");
            for (int i = 0; i < outs.size(); i++) {
                UTXO u = p.getUtxo(txid, i);
                assertNotNull(u, name + " vout " + i);
                assertEquals(txid, u.txid(), name);
                assertEquals(i, u.outputIndex(), name);
                assertEquals(Json.asLong(outs.get(i).get("satoshis")), u.satoshis(), name + " vout " + i + " satoshis");
                assertEquals(2 * Json.asLong(outs.get(i).get("scriptLen")), u.scriptHex().length(), name);
                assertEquals(outs.get(i).get("scriptSha256"), sha256Hex(u.scriptHex()), name);
            }
            assertNull(p.getUtxo(txid, outs.size()), name + ": vout past the end");
            assertEquals(rawUrl(txid), f.urls.get(0));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void getUtxoRejectsBodyForAnotherTxid() throws Exception {
        Map<String, Object> doc = loadGorillaPoolVectors();
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) doc.get("vectors");
        for (Map<String, Object> rv : (List<Map<String, Object>>) doc.get("rejection_vectors")) {
            String requested = (String) rv.get("requestedTxid");
            Map<String, Object> src = vectors.stream()
                .filter(v -> v.get("name").equals(rv.get("responseOf"))).findFirst().orElseThrow();
            FakeRawFetcher f = new FakeRawFetcher(rawUrl(requested),
                ScriptUtils.hexToBytes((String) src.get("responseHex")));
            GorillaPoolProvider p = new GorillaPoolProvider("mainnet", new FakeTransport(), f);
            ProviderException pe = assertThrows(ProviderException.class, () -> p.getUtxo(requested, 0));
            assertTrue(pe.getMessage().contains("txid mismatch"), pe.getMessage());
        }
    }

    @Test
    void getUtxoThrowsOn404() {
        // F-027: the 404 now comes from the binary /tx/{txid}/raw fetch.
        // N-025: a 404 on this documented route throws; it is no longer null.
        FakeRawFetcher f = new FakeRawFetcher("nothing-matches", new byte[0]);
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", new FakeTransport(), f);
        ProviderException pe = assertThrows(ProviderException.class, () -> p.getUtxo("ab".repeat(32), 0));
        assertEquals(404, pe.statusCode());
    }

    // ------------------------------------------------------------------
    // getRawTransaction
    // ------------------------------------------------------------------

    // N-025: replaces getRawTransactionTrimsBody, which pinned the undocumented
    // /tx/{txid}/hex route (a 404 on the live API).
    @Test
    @SuppressWarnings("unchecked")
    void getRawTransactionReturnsVerifiedRawRouteAsHex() throws Exception {
        Map<String, Object> v = ((List<Map<String, Object>>) loadGorillaPoolVectors().get("vectors")).get(0);
        String txid = (String) v.get("txid");
        FakeRawFetcher f = new FakeRawFetcher(rawUrl(txid), ScriptUtils.hexToBytes((String) v.get("responseHex")));
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", new FakeTransport(), f);
        assertEquals(v.get("responseHex"), p.getRawTransaction(txid));
        assertEquals(rawUrl(txid), f.urls.get(0));
        assertThrows(ProviderException.class, () -> p.getRawTransaction("ab".repeat(32)));
    }

    // ------------------------------------------------------------------
    // Token helpers
    // ------------------------------------------------------------------

    // N-025: the balance/utxo tests below replace ones that pinned the
    // undocumented /bsv20/balance/{a}/{x} and /bsv20/utxos/{a}/{x} routes (404s
    // on the live API) and mapped their 404 to "0" / an empty list.
    private static final String BALANCES =
        "[{\"all\":{\"confirmed\":\"123456\",\"pending\":\"5\"},\"listed\":{\"confirmed\":\"0\",\"pending\":\"0\"},\"tick\":\"DOGE\",\"dec\":0},"
            + "{\"all\":{\"confirmed\":\"7\",\"pending\":\"0\"},\"listed\":{\"confirmed\":\"0\",\"pending\":\"0\"},\"id\":\"abcd_0\",\"sym\":\"X\",\"dec\":0}]";

    @Test
    void getBSV20BalanceReadsConfirmedFromDocumentedListing() {
        FakeTransport t = new FakeTransport().queue(200, BALANCES);
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("123456", p.getBSV20Balance("1ADDR", "DOGE"));
        assertEquals("https://ordinals.gorillapool.io/api/bsv20/1ADDR/balance", t.calls.get(0).url());
    }

    @Test
    void getBSV21BalanceMatchesOnId() {
        FakeTransport t = new FakeTransport().queue(200, BALANCES).queue(200, BALANCES);
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("7", p.getBSV21Balance("a", "abcd_0"));
        assertEquals("0", p.getBSV20Balance("a", "abcd_0"), "an id is not a tick");
    }

    @Test
    void getBSV20BalanceIsZeroWhenTokenNotHeldButThrowsOn404() {
        FakeTransport t = new FakeTransport().queue(200, BALANCES).queue(404, "{\"message\":\"Not Found\"}");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        assertEquals("0", p.getBSV20Balance("a", "NOPE"));
        ProviderException pe = assertThrows(ProviderException.class, () -> p.getBSV20Balance("a", "DOGE"));
        assertEquals(404, pe.statusCode());
    }

    @Test
    void getBSV21UtxosUrlEncodesId() {
        FakeTransport t = new FakeTransport().queue(200, "[]");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        p.getBSV21Utxos("1ADDR", "abcd_0");
        assertTrue(t.calls.get(0).url().endsWith("/bsv20/1ADDR/id/abcd_0"),
            t.calls.get(0).url());
    }

    @Test
    void getBSV20UtxosDecodesBase64ScriptAndRefusesMissingScript() {
        FakeTransport t = new FakeTransport()
            .queue(200, "[{\"txid\":\"" + "aa".repeat(32) + "\",\"vout\":2,\"satoshis\":1,\"script\":\"dqkU\"}]")
            .queue(200, "[{\"txid\":\"" + "aa".repeat(32) + "\",\"vout\":2,\"satoshis\":1}]");
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        List<UTXO> got = p.getBSV20Utxos("1ADDR", "DOGE");
        assertEquals("76a914", got.get(0).scriptHex());
        assertTrue(t.calls.get(0).url().endsWith("/bsv20/1ADDR/tick/DOGE"), t.calls.get(0).url());
        assertThrows(ProviderException.class, () -> p.getBSV20Utxos("1ADDR", "DOGE"));
    }

    // ------------------------------------------------------------------
    // Contract UTXO helper
    // ------------------------------------------------------------------

    // N-025: replaces getContractUtxosHitsScriptEndpoint / getContractUtxosReturnsEmptyOn404.
    // /script/{hash}/utxos is not a GorillaPool route (404 live), so the old
    // method always reported "no UTXOs". It now refuses without a request.
    @Test
    void getContractUtxosRefusesWithoutARequest() {
        FakeTransport t = new FakeTransport();
        GorillaPoolProvider p = new GorillaPoolProvider("mainnet", t);
        ProviderException pe = assertThrows(ProviderException.class, () -> p.getContractUtxos("ff".repeat(32)));
        assertTrue(pe.getMessage().contains("not supported"), pe.getMessage());
        assertTrue(t.calls.isEmpty());
    }
}
