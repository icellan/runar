package runar.lang.sdk;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REST {@link Provider} backed by the WhatsOnChain BSV API.
 * Parity with {@code packages/runar-go/sdk_woc_provider.go}.
 *
 * <p>Endpoints:
 * <ul>
 *     <li>Mainnet: {@code https://api.whatsonchain.com/v1/bsv/main}</li>
 *     <li>Testnet: {@code https://api.whatsonchain.com/v1/bsv/test}</li>
 * </ul>
 *
 * <p>{@link #listUtxos(String)} hits {@code /address/{addr}/unspent} (returns
 * outpoints + values; the locking script is not in the listing, so each UTXO's
 * script is read from the verified {@code /tx/{txid}/hex}). {@link #broadcastRaw(String)}
 * POSTs to {@code /tx/raw} with a {@code {"txhex":"..."}} body. WoC returns
 * the txid as a JSON-encoded string.
 */
public final class WhatsOnChainProvider implements Provider {

    private final String network;
    private final String baseUrl;
    private final HttpTransport transport;

    /** Explicitly selects mainnet. Use {@link #WhatsOnChainProvider(String)} to choose. */
    public WhatsOnChainProvider() {
        this("mainnet", HttpTransport.jdkDefault());
    }

    public WhatsOnChainProvider(String network) {
        this(network, HttpTransport.jdkDefault());
    }

    // Package-private full constructor so tests can inject a fake transport.
    WhatsOnChainProvider(String network, HttpTransport transport) {
        // Network must be exactly "mainnet" or "testnet". Any other value —
        // including null and the empty string — is rejected rather than
        // defaulted, so a typo or an unvalidated user-supplied value can never
        // silently point the SDK at live mainnet.
        if (!"mainnet".equals(network) && !"testnet".equals(network)) {
            throw new IllegalArgumentException(
                "invalid network " + (network == null ? "null" : "\"" + network + "\"")
                    + ": must be \"mainnet\" or \"testnet\"");
        }
        this.network = network;
        this.baseUrl = "testnet".equals(network)
            ? "https://api.whatsonchain.com/v1/bsv/test"
            : "https://api.whatsonchain.com/v1/bsv/main";
        this.transport = transport == null ? HttpTransport.jdkDefault() : transport;
    }

    public String getNetwork() {
        return network;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    // ------------------------------------------------------------------
    // Provider
    // ------------------------------------------------------------------

    /**
     * WoC's GET /address/{address}/unspent listing carries outpoints and
     * values but no locking script. The script is the BIP-143 scriptCode a
     * signer commits to, so an empty one yields signatures no OP_CHECKSIG
     * accepts (F-040). Each distinct txid is therefore fetched via
     * GET /tx/{txid}/hex, its double-SHA256 must equal the txid, and tx_pos
     * must be an output whose value equals the listed value. Any failure
     * throws; no UTXO is returned with an empty script.
     *
     * <p>Note: WoC caps this legacy listing at about 1000 entries, so an
     * address holding more UTXOs is returned truncated.
     */
    @Override
    public List<UTXO> listUtxos(String address) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/address/" + address + "/unspent", null, null);
        if (resp.statusCode() == 404) return List.of();
        requireOk(resp, "WoC getUtxos");

        Object parsed = parseJson(resp.body(), "WoC getUtxos");
        if (!(parsed instanceof List<?> entries)) {
            throw new ProviderException("WoC getUtxos: expected JSON array, got " + typeName(parsed));
        }
        Map<String, RawTx> txs = new HashMap<>();
        List<UTXO> utxos = new ArrayList<>(entries.size());
        for (Object e : entries) {
            Map<String, Object> u = Json.asObject(e);
            String txid = Json.asString(u.get("tx_hash"));
            int pos = Json.asInt(u.get("tx_pos"));
            long value = Json.asLong(u.get("value"));
            RawTx tx = txs.get(txid);
            if (tx == null) {
                tx = fetchVerifiedTx(txid, "getUtxos");
                txs.put(txid, tx);
            }
            if (pos < 0 || pos >= tx.outputs.size()) {
                throw new ProviderException("WoC getUtxos: no output " + pos + " in tx " + txid
                    + " (" + tx.outputs.size() + " outputs)");
            }
            RawTx.Output out = tx.outputs.get(pos);
            if (out.satoshis != value) {
                throw new ProviderException("WoC getUtxos: value mismatch for " + txid + ":" + pos
                    + ": listing says " + value + ", tx says " + out.satoshis);
            }
            String script = out.scriptPubKeyHex == null ? "" : out.scriptPubKeyHex;
            if (script.isEmpty()) {
                throw new ProviderException("WoC getUtxos: empty locking script for " + txid + ":" + pos);
            }
            ScriptSizeExceededError.assertScriptHexUnderLimit(
                script, InputLimits.MAX_SCRIPT_BYTES,
                "WhatsOnChainProvider.listUtxos(" + address + ")"
            );
            utxos.add(new UTXO(txid, pos, value, script));
        }
        return utxos;
    }

    /** GET /tx/{txid}/hex, required to hash to {@code txid} (F-040 / N-041). */
    private RawTx fetchVerifiedTx(String txid, String context) {
        String rawHex = getRawTransaction(txid);
        if (!rawHex.matches("(?:[0-9a-fA-F]{2})*")) {
            throw new ProviderException("WoC " + context + ": /tx/" + txid + "/hex body is not hex");
        }
        byte[] raw = ScriptUtils.hexToBytes(rawHex);
        String bodyTxid = ScriptUtils.reverseHex(ScriptUtils.bytesToHex(Hash160.doubleSha256(raw)));
        if (!bodyTxid.equals(txid.toLowerCase(java.util.Locale.ROOT))) {
            throw new ProviderException("WoC " + context + ": txid mismatch: /tx/" + txid
                + "/hex body hashes to " + bodyTxid);
        }
        try {
            return RawTxParser.parse(rawHex.toLowerCase(java.util.Locale.ROOT));
        } catch (RuntimeException re) {
            throw new ProviderException("WoC " + context + ": parsing tx " + txid + ": " + re.getMessage(), re);
        }
    }

    @Override
    public String broadcastRaw(String txHex) {
        if (txHex == null || txHex.isEmpty()) {
            throw new IllegalArgumentException("WhatsOnChainProvider.broadcastRaw: txHex is required");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("txhex", txHex);
        Map<String, String> headers = Map.of("Content-Type", "application/json");

        HttpTransport.Response resp = transport.send(
            "POST", baseUrl + "/tx/raw", headers, JsonWriter.write(payload));
        requireOk(resp, "WoC broadcast");

        // WoC returns the txid as a JSON-encoded string ("\"abcd...\"").
        Object parsed = parseJson(resp.body(), "WoC broadcast");
        if (!(parsed instanceof String txid)) {
            throw new ProviderException("WoC broadcast: expected JSON string, got " + typeName(parsed));
        }
        return txid;
    }

    /**
     * N-041: GET /tx/hash/{txid} has no {@code hex} field and reports values
     * as float BSV, and its script is unverifiable. The serialized tx is
     * fetched via GET /tx/{txid}/hex instead, its double-SHA256 must equal the
     * txid, and the output's script and exact satoshis are read from those
     * bytes. A 404 or an out-of-range {@code vout} returns {@code null}; an
     * empty locking script throws.
     */
    @Override
    public UTXO getUtxo(String txid, int vout) {
        RawTx tx;
        try {
            tx = fetchVerifiedTx(txid, "getTransaction");
        } catch (ProviderException pe) {
            if (pe.statusCode() == 404) return null;
            throw pe;
        }
        if (vout < 0 || vout >= tx.outputs.size()) return null;
        RawTx.Output out = tx.outputs.get(vout);
        String script = out.scriptPubKeyHex == null ? "" : out.scriptPubKeyHex;
        if (script.isEmpty()) {
            throw new ProviderException("WoC getTransaction: empty locking script for " + txid + ":" + vout);
        }
        ScriptSizeExceededError.assertScriptHexUnderLimit(
            script, InputLimits.MAX_SCRIPT_BYTES,
            "WhatsOnChainProvider.getUtxo(" + txid + ":" + vout + ")"
        );
        return new UTXO(txid, vout, out.satoshis, script);
    }

    /**
     * Fetches the raw transaction hex by txid via {@code /tx/{txid}/hex}.
     * Mirrors {@code WhatsOnChainProvider.GetRawTransaction} in the Go SDK.
     */
    public String getRawTransaction(String txid) {
        HttpTransport.Response resp = transport.send(
            "GET", baseUrl + "/tx/" + txid + "/hex", null, null);
        requireOk(resp, "WoC getRawTransaction");
        return resp.body() == null ? "" : resp.body().trim();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static void requireOk(HttpTransport.Response resp, String op) {
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new ProviderException(
                op + " failed (" + resp.statusCode() + "): "
                    + RPCProvider.truncate(resp.body(), 256),
                resp.statusCode());
        }
    }

    private static Object parseJson(String body, String op) {
        try {
            return Json.parse(body);
        } catch (RuntimeException re) {
            throw new ProviderException(op + " JSON decode failed: " + re.getMessage(), re);
        }
    }

    private static String typeName(Object v) {
        return v == null ? "null" : v.getClass().getSimpleName();
    }
}
