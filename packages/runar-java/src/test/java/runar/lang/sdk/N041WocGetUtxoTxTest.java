package runar.lang.sdk;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-041: {@code WhatsOnChainProvider.getUtxo} (the Java tier's per-outpoint
 * transaction lookup; the Java WoC provider has no getContractUtxo /
 * getTransaction) read GET /tx/hash/{txid}, whose JSON has no {@code hex}
 * field and reports values as float BSV, and took the output script from that
 * unverified JSON. {@code OpPushTx.preimage} accepted an empty scriptCode.
 *
 * <p>Proves, with conformance/sdk-woc/contract-utxo-tx-vectors.json and a
 * stub transport: getUtxo reads the hash-verified GET /tx/{txid}/hex and
 * returns each output's real script and exact satoshis (21e14 scale), refuses
 * a body that hashes to another txid, and still returns null for a 404 or an
 * out-of-range vout; OpPushTx.preimage refuses an empty scriptCode.
 * Does NOT prove: that the live WoC API keeps these shapes (recorded
 * 2026-09-29). Java's ExternalSigner signs a precomputed digest, so its
 * empty-subscript guard is RawTx.sighashBIP143 (F040WocUtxoScriptTest).
 */
class N041WocGetUtxoTxTest {

    private static final String BASE = "https://api.whatsonchain.com/v1/bsv/main";

    /** Serves exact URLs from routes; 404 otherwise. */
    private static final class RoutingTransport implements HttpTransport {
        final Map<String, String> routes = new HashMap<>();

        @Override
        public Response send(String method, String url, Map<String, String> headers, String body) {
            String b = routes.get(url);
            return b == null ? new Response(404, "Not Found") : new Response(200, b);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getTransactionVectors() throws Exception {
        java.nio.file.Path p = java.nio.file.Paths.get(System.getProperty("user.dir"),
            "..", "..", "conformance", "sdk-woc", "contract-utxo-tx-vectors.json");
        Map<String, Object> v = (Map<String, Object>) Json.parse(java.nio.file.Files.readString(p));
        return (Map<String, Object>) v.get("getTransaction");
    }

    private static WhatsOnChainProvider serving(String txid, String rawHex, String hashBody) {
        RoutingTransport t = new RoutingTransport();
        if (rawHex != null) t.routes.put(BASE + "/tx/" + txid + "/hex", rawHex);
        if (hashBody != null) t.routes.put(BASE + "/tx/hash/" + txid, hashBody);
        return new WhatsOnChainProvider("mainnet", t);
    }

    @Test
    @SuppressWarnings("unchecked")
    void getUtxoReturnsVerifiedScriptAndExactSatoshis() throws Exception {
        List<Map<String, Object>> cases = (List<Map<String, Object>>) getTransactionVectors().get("cases");
        assertFalse(cases.isEmpty());
        for (Map<String, Object> c : cases) {
            String txid = (String) c.get("txid");
            // Only /tx/{txid}/hex is served: the unverifiable /tx/hash JSON must not be needed.
            WhatsOnChainProvider p = serving(txid, (String) c.get("rawTxHex"), null);
            List<Map<String, Object>> outs = (List<Map<String, Object>>) ((Map<String, Object>) c.get("expected")).get("outputs");
            for (int vout = 0; vout < outs.size(); vout++) {
                UTXO u = p.getUtxo(txid, vout);
                assertNotNull(u, c.get("name") + ":" + vout);
                assertEquals(txid, u.txid());
                assertEquals(vout, u.outputIndex());
                assertEquals(Json.asLong(outs.get(vout).get("satoshis")), u.satoshis(), c.get("name") + ":" + vout);
                assertEquals(outs.get(vout).get("script"), u.scriptHex(), c.get("name") + ":" + vout);
            }
            assertNull(p.getUtxo(txid, outs.size()), "out-of-range vout");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void getUtxoRejectionVectors() throws Exception {
        for (Map<String, Object> rv : (List<Map<String, Object>>) getTransactionVectors().get("rejection_vectors")) {
            String name = (String) rv.get("name");
            String txid = (String) rv.get("txid");
            WhatsOnChainProvider p = serving(txid, (String) rv.get("rawTxHex"), (String) rv.get("hashBody"));
            if ("raw-tx-unavailable".equals(name)) {
                assertNull(p.getUtxo(txid, 0), name);
                continue;
            }
            RuntimeException ex = assertThrows(RuntimeException.class, () -> p.getUtxo(txid, 0), name);
            assertTrue(ex.getMessage().contains((String) rv.get("error")),
                name + ": error '" + ex.getMessage() + "' does not contain '" + rv.get("error") + "'");
        }
    }

    @Test
    void opPushTxPreimageRefusesEmptyScriptCode() {
        RawTx tx = new RawTx();
        tx.addInput("11".repeat(32), 0, "");
        tx.addOutput(900L, "51");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> OpPushTx.preimage(tx, 0, new byte[0], 1000L, OpPushTx.SIGHASH_ALL_FORKID));
        assertTrue(ex.getMessage().contains("empty subscript"), ex.getMessage());
    }
}
