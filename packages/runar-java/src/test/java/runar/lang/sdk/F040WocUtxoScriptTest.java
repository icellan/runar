package runar.lang.sdk;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * F-040: {@code WhatsOnChainProvider.listUtxos} returned an empty script for
 * every UTXO, because WoC's GET /address/{a}/unspent listing carries no
 * locking script. That empty string became the BIP-143 scriptCode in
 * {@code RawTx.sighashBIP143} (the Java tier's signers sign a precomputed
 * digest, so this is where the subscript enters), so every funding signature
 * was computed over a zero-length scriptCode no real P2PKH OP_CHECKSIG accepts.
 *
 * <p>Proves: with the shared recorded responses (conformance/sdk-woc/vectors.json)
 * listUtxos fetches GET /tx/{txid}/hex per UTXO and returns the real locking
 * script; it fails loudly on a body for another txid, a missing output, a
 * value that disagrees with the tx, an unavailable tx and an empty output
 * script; and the BIP-143 digest (directly and via WalletProvider.computeSighash)
 * refuses an empty subscript.
 * Does NOT prove: that the live WoC API still serves these shapes (vectors
 * recorded 2026-09-29), or anything about getUtxo. The Spend.validate harm demo
 * lives in packages/runar-sdk/src/__tests__/f040-woc-utxo-script.test.ts.
 */
class F040WocUtxoScriptTest {

    private static final String BASE = "https://api.whatsonchain.com/v1/bsv/main";
    private static final Pattern TX_HEX = Pattern.compile("/tx/([0-9a-f]{64})/hex$");

    /** Serves the listing and each raw tx at /tx/{txid}/hex; 404 otherwise. */
    private static final class RoutingTransport implements HttpTransport {
        final String address;
        final String unspentBody;
        final Map<String, Object> rawTxHex;
        final List<String> urls = new ArrayList<>();

        RoutingTransport(String address, String unspentBody, Map<String, Object> rawTxHex) {
            this.address = address;
            this.unspentBody = unspentBody;
            this.rawTxHex = rawTxHex;
        }

        @Override
        public Response send(String method, String url, Map<String, String> headers, String body) {
            urls.add(url);
            if (url.equals(BASE + "/address/" + address + "/unspent")) return new Response(200, unspentBody);
            Matcher m = TX_HEX.matcher(url);
            if (m.find() && rawTxHex.containsKey(m.group(1))) {
                return new Response(200, (String) rawTxHex.get(m.group(1)));
            }
            return new Response(404, "Not Found");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> vectors() throws Exception {
        java.nio.file.Path p = java.nio.file.Paths.get(System.getProperty("user.dir"),
            "..", "..", "conformance", "sdk-woc", "vectors.json");
        return (Map<String, Object>) Json.parse(java.nio.file.Files.readString(p));
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUtxosReturnsRecordedLockingScripts() throws Exception {
        Map<String, Object> v = vectors();
        String address = (String) v.get("address");
        WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", new RoutingTransport(
            address, (String) v.get("unspentBody"), (Map<String, Object>) v.get("rawTxHex")));

        List<UTXO> got = p.listUtxos(address);
        List<Map<String, Object>> expected = (List<Map<String, Object>>) v.get("expected");
        assertEquals(expected.size(), got.size());
        for (int i = 0; i < expected.size(); i++) {
            Map<String, Object> e = expected.get(i);
            UTXO u = got.get(i);
            assertEquals(e.get("txid"), u.txid());
            assertEquals(Json.asInt(e.get("outputIndex")), u.outputIndex());
            assertEquals(Json.asLong(e.get("satoshis")), u.satoshis());
            assertEquals(e.get("script"), u.scriptHex());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUtxosRejectionVectors() throws Exception {
        Map<String, Object> v = vectors();
        String address = (String) v.get("address");
        List<Map<String, Object>> rejections = (List<Map<String, Object>>) v.get("rejection_vectors");
        assertFalse(rejections.isEmpty());
        for (Map<String, Object> rv : rejections) {
            String name = (String) rv.get("name");
            String want = (String) rv.get("error");
            WhatsOnChainProvider p = new WhatsOnChainProvider("mainnet", new RoutingTransport(
                address, (String) rv.get("unspentBody"), (Map<String, Object>) rv.get("rawTxHex")));
            RuntimeException ex = assertThrows(RuntimeException.class, () -> p.listUtxos(address),
                name + ": expected an error");
            assertTrue(ex.getMessage().contains(want),
                name + ": error '" + ex.getMessage() + "' does not contain '" + want + "'");
        }
    }

    private static RawTx spendTx() {
        RawTx tx = new RawTx();
        tx.addInput("11".repeat(32), 0, "");
        tx.addOutput(900L, "51");
        return tx;
    }

    @Test
    void sighashBIP143RefusesEmptySubscript() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> spendTx().sighashBIP143(0, "", 1000L, RawTx.SIGHASH_ALL_FORKID));
        assertTrue(ex.getMessage().contains("empty subscript"), ex.getMessage());
    }

    @Test
    void walletProviderComputeSighashRefusesEmptySubscript() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> WalletProvider.computeSighash(spendTx().toHex(), 0, "", 1000L));
        assertTrue(ex.getMessage().contains("empty subscript"), ex.getMessage());
    }
}
