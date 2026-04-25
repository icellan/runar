package runar.lang.sdk.ordinals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import runar.lang.sdk.Provider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.Signer;
import runar.lang.sdk.UTXO;

/**
 * Lightweight BSV-20 / BSV-21 token UTXO holder. Java mirror of the
 * Zig {@code TokenWallet} in
 * {@code packages/runar-zig/src/sdk_token_wallet.zig} (which itself
 * mirrors the TS / Go / Rust / Python / Ruby variants).
 *
 * <p>Wraps a compiled {@link RunarArtifact}, a {@link Provider}, and
 * a {@link Signer}, and provides UTXO-list filtering keyed off the
 * artifact's locking-script prefix. The full transfer / merge
 * lifecycle requires the high-level {@code RunarContract} surface and
 * lives there; this class is a small composable building block.
 */
public final class TokenWallet {

    private final RunarArtifact artifact;
    private final Provider provider;
    private final Signer signer;

    public TokenWallet(RunarArtifact artifact, Provider provider, Signer signer) {
        this.artifact = Objects.requireNonNull(artifact, "artifact");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.signer = Objects.requireNonNull(signer, "signer");
    }

    public RunarArtifact getArtifact() { return artifact; }
    public Provider getProvider() { return provider; }
    public Signer getSigner() { return signer; }

    /**
     * Returns all token UTXOs associated with the wallet's signer
     * address, filtered to only those whose locking script begins
     * with the artifact's {@code scriptHex} prefix.
     *
     * <p>An empty artifact prefix disables filtering and returns all
     * UTXOs — parity with the Zig implementation.
     */
    public List<UTXO> getUtxos() {
        String addr = signer.address();
        List<UTXO> all = provider.listUtxos(addr);
        if (all == null || all.isEmpty()) return Collections.emptyList();

        String prefix = artifact.scriptHex();
        if (prefix == null || prefix.isEmpty()) {
            return new ArrayList<>(all);
        }

        List<UTXO> out = new ArrayList<>();
        for (UTXO u : all) {
            String script = u.scriptHex();
            if (script == null) continue;
            if (script.length() >= prefix.length() && script.startsWith(prefix)) {
                out.add(u);
            }
        }
        return out;
    }

    /**
     * Pick the first candidate from a list. Throws
     * {@link IllegalStateException} when {@code candidates} is empty.
     * Matches the Zig {@code pickCandidate} contract; full balance
     * decoding is out of scope here and lives in {@code RunarContract}.
     */
    public static UTXO pickCandidate(List<UTXO> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            throw new IllegalStateException("TokenWallet.pickCandidate: no UTXOs");
        }
        return candidates.get(0);
    }
}
