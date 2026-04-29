package runar.integration.helpers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import runar.lang.sdk.Provider;
import runar.lang.sdk.UTXO;

/**
 * {@link Provider} implementation backed by a Bitcoin SV regtest node
 * (SV Node or Teranode). Used only by the integration tests — parity
 * with the Python {@code RPCProvider}, Rust {@code RpcProvider}, and Go
 * {@code BatchRPCProvider}.
 *
 * <p>The Java SDK ships {@link runar.lang.sdk.MockProvider} for unit
 * tests but does not yet include an on-chain RPC provider (M8 scope);
 * this test-only helper fills the gap until the SDK adds one natively.
 *
 * <p>Auto-mining: calling {@link #broadcastRaw} triggers a single-block
 * mine so subsequent UTXO lookups see the broadcast tx. On Teranode
 * this also nudges the validator/blockassembly services to pick up the
 * tx promptly.
 */
public final class RpcProvider implements Provider {

    private final RpcClient rpc;
    private final boolean autoMine;

    public RpcProvider(RpcClient rpc) {
        this(rpc, true);
    }

    public RpcProvider(RpcClient rpc, boolean autoMine) {
        this.rpc = rpc;
        this.autoMine = autoMine;
    }

    public RpcClient rpc() { return rpc; }

    @Override
    public List<UTXO> listUtxos(String address) {
        // Use listunspent — works on SV Node with a wallet-imported address.
        // On Teranode (no wallet) this call returns an empty list; tests
        // funding Teranode addresses must use the raw-coinbase path in
        // integration/teranode-compose instead.
        String result;
        try {
            result = rpc.call("listunspent", 0L, 9_999_999L, List.of(address));
        } catch (Exception e) {
            // Teranode / wallet-less node: no unspent list available.
            return List.of();
        }
        Object parsed = new JsonReader(result).readValue();
        if (!(parsed instanceof List<?> arr)) return List.of();
        List<UTXO> out = new ArrayList<>();
        for (Object item : arr) {
            if (!(item instanceof Map<?, ?> m)) continue;
            String txid = (String) m.get("txid");
            Number voutN = (Number) m.get("vout");
            if (txid == null || voutN == null) continue;
            // "amount" is BTC on SV Node (float), satoshis on Teranode (int).
            long sats = satoshisFromAmount(m.get("amount"));
            String script = (String) m.get("scriptPubKey");
            if (script == null) continue;
            out.add(new UTXO(txid, voutN.intValue(), sats, script));
        }
        return out;
    }

    @Override
    public String broadcastRaw(String txHex) {
        int sizeBytes = txHex == null ? 0 : txHex.length() / 2;
        System.out.println("[runar-integration] tx broadcast: " + sizeBytes + " bytes");
        String result = rpc.call("sendrawtransaction", txHex);
        // sendrawtransaction returns a bare JSON string (the txid).
        String txid = result.trim();
        if (txid.startsWith("\"") && txid.endsWith("\"")) {
            txid = txid.substring(1, txid.length() - 1);
        }
        if (autoMine) {
            try {
                rpc.mine(1);
            } catch (Exception ignored) { /* best effort */ }
        }
        return txid;
    }

    @Override
    public UTXO getUtxo(String txid, int vout) {
        String result;
        try {
            // Verbose mode: SV Node accepts bool `true`, Teranode accepts int `1`.
            Object verboseFlag = rpc.isTeranode() ? Integer.valueOf(1) : Boolean.TRUE;
            result = rpc.call("getrawtransaction", txid, verboseFlag);
        } catch (Exception e) {
            return null;
        }
        Object parsed = new JsonReader(result).readValue();
        if (!(parsed instanceof Map<?, ?> m)) return null;
        Object vouts = m.get("vout");
        if (!(vouts instanceof List<?> voutList)) return null;
        if (vout < 0 || vout >= voutList.size()) return null;
        Object voutItem = voutList.get(vout);
        if (!(voutItem instanceof Map<?, ?> vm)) return null;
        long sats = satoshisFromAmount(vm.get("value"));
        String script = null;
        Object spk = vm.get("scriptPubKey");
        if (spk instanceof Map<?, ?> spkMap) {
            Object hex = spkMap.get("hex");
            if (hex instanceof String s) script = s;
        }
        if (script == null) return null;
        return new UTXO(txid, vout, sats, script);
    }

    @Override
    public long getFeeRate() {
        // BSV default: 100 sat/KB. Regtest mempool accepts anything > 1, but
        // 100 keeps the rendered txs aligned with the other SDK test suites.
        return 100L;
    }

    private static long satoshisFromAmount(Object amount) {
        if (amount == null) return 0L;
        if (amount instanceof Number n) {
            double d = n.doubleValue();
            // SV Node returns BTC decimals (e.g. 50.0); Teranode returns satoshis (e.g. 5000000000).
            // A value >= 1e7 is definitely satoshis (anything over 0.1 BTC in BTC-decimals would be
            // absurdly large in the integration test funding path).
            if (d >= 1_000_000d) {
                return (long) d;
            }
            return Math.round(d * 1e8);
        }
        return 0L;
    }
}
