package runar.lang.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In-memory {@link Provider} for tests. Parity with
 * {@code packages/runar-go/sdk_provider.go} {@code MockProvider}.
 *
 * <p>Tests inject UTXOs via {@link #addUtxo(String, UTXO)} and inspect
 * broadcasts via {@link #getBroadcastedTxs()}.
 */
public final class MockProvider implements Provider {

    private final Map<String, List<UTXO>> utxosByAddress = new HashMap<>();
    private final Map<String, UTXO> utxosByOutpoint = new HashMap<>();
    private final List<String> broadcasted = new ArrayList<>();
    private final String network;
    private int broadcastCount = 0;
    private long feeRate = 100L;

    public MockProvider() {
        this("testnet");
    }

    public MockProvider(String network) {
        this.network = (network == null || network.isEmpty()) ? "testnet" : network;
    }

    public String getNetwork() {
        return network;
    }

    public void addUtxo(String address, UTXO utxo) {
        utxosByAddress.computeIfAbsent(address, k -> new ArrayList<>()).add(utxo);
        utxosByOutpoint.put(outpointKey(utxo.txid(), utxo.outputIndex()), utxo);
    }

    public List<String> getBroadcastedTxs() {
        return Collections.unmodifiableList(broadcasted);
    }

    public void setFeeRate(long rate) {
        this.feeRate = rate;
    }

    @Override
    public long getFeeRate() {
        return feeRate;
    }

    @Override
    public List<UTXO> listUtxos(String address) {
        return new ArrayList<>(utxosByAddress.getOrDefault(address, Collections.emptyList()));
    }

    @Override
    public String broadcastRaw(String txHex) {
        broadcasted.add(txHex);
        broadcastCount++;
        String prefix = txHex.length() >= 16 ? txHex.substring(0, 16) : txHex;
        return mockHash64("mock-broadcast-" + broadcastCount + "-" + prefix);
    }

    @Override
    public UTXO getUtxo(String txid, int vout) {
        return utxosByOutpoint.get(outpointKey(txid, vout));
    }

    private static String outpointKey(String txid, int vout) {
        return txid + ":" + vout;
    }

    // ------------------------------------------------------------------
    // Deterministic mock hash (matches Go mockHash64)
    // ------------------------------------------------------------------

    static String mockHash64(String input) {
        int h0 = 0x6a09e667;
        int h1 = 0xbb67ae85;
        int h2 = 0x3c6ef372;
        int h3 = 0xa54ff53a;
        for (int i = 0; i < input.length(); i++) {
            int c = input.charAt(i) & 0xff;
            h0 = (h0 ^ c) * 0x01000193;
            h1 = (h1 ^ c) * 0x01000193;
            h2 = (h2 ^ c) * 0x01000193;
            h3 = (h3 ^ c) * 0x01000193;
        }
        int[] parts = {h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3};
        StringBuilder sb = new StringBuilder(64);
        for (int p : parts) {
            sb.append(String.format("%08x", p));
        }
        return sb.toString();
    }
}
