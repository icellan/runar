package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Optional knobs for {@link RunarContract#call} and
 * {@link RunarContract#prepareCall}. All fields are nullable; pass
 * {@code null} (or omit the {@code CallOptions} arg entirely) for the
 * default flow (provider-fetched funding, automatic state continuation,
 * automatic change to the signer's address).
 *
 * <p>Parity targets: Go {@code CallOptions} (sdk_types.go), Zig
 * {@code CallOptions} (sdk_types.zig), TypeScript {@code CallOptions}
 * (runar-sdk).
 */
public final class CallOptions {

    /**
     * Explicit state-update overrides. When non-null, these win over the
     * ANF interpreter's auto-computed state for stateful contracts. Use
     * for tests or when the caller already knows the post-call state.
     */
    public final Map<String, Object> newState;

    /**
     * Terminal outputs that fully spend the contract. When non-null:
     * <ul>
     *   <li>The transaction is built with the contract UTXO as the only
     *       signed contract input (plus any {@link #fundingUtxos} as
     *       P2PKH funding inputs).</li>
     *   <li>The output list is exactly these entries — no automatic
     *       state continuation, no change output.</li>
     *   <li>The fee comes from the contract balance + funding UTXOs.</li>
     *   <li>After a successful call the contract is fully spent
     *       ({@code currentUtxo} becomes {@code null}).</li>
     * </ul>
     */
    public final List<TerminalOutput> terminalOutputs;

    /**
     * Additional P2PKH funding UTXOs to include as inputs for terminal
     * method calls. Only consulted when {@link #terminalOutputs} is
     * non-null. Each UTXO is signed with the configured signer's key.
     */
    public final List<UTXO> fundingUtxos;

    public CallOptions(
        Map<String, Object> newState,
        List<TerminalOutput> terminalOutputs,
        List<UTXO> fundingUtxos
    ) {
        this.newState = newState;
        this.terminalOutputs = terminalOutputs;
        this.fundingUtxos = fundingUtxos;
    }

    /** Convenience factory for the common terminal-call case. */
    public static CallOptions terminal(List<TerminalOutput> outputs) {
        return new CallOptions(null, outputs, null);
    }

    /**
     * One output emitted from a terminal method call. Either {@code address}
     * (resolved to a P2PKH locking script) or {@code scriptHex} (used as
     * the locking script directly) must be set.
     */
    public record TerminalOutput(BigInteger satoshis, String address, String scriptHex) {

        public TerminalOutput {
            if (satoshis == null) {
                throw new IllegalArgumentException("TerminalOutput: satoshis must not be null");
            }
            if ((address == null) == (scriptHex == null)) {
                throw new IllegalArgumentException(
                    "TerminalOutput: exactly one of address or scriptHex must be set"
                );
            }
        }

        /**
         * Resolve {@link #address} or {@link #scriptHex} into the raw
         * hex-encoded locking script for tx output construction.
         */
        public String resolveScriptHex() {
            return scriptHex != null ? scriptHex : ScriptUtils.buildP2PKHScript(address);
        }
    }
}
