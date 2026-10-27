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

    /**
     * Override the call tx's nLockTime field. {@code null} → SDK uses 0
     * (legacy behavior, preserves existing contracts). Set for contracts
     * that assert {@code extractLocktime(preimage) >= deadline} (e.g.
     * auction {@code close}/{@code claim} methods). Threaded through both
     * the non-terminal and terminal call-tx build sites.
     */
    public final Integer locktime;

    /**
     * Override the nSequence written onto EVERY input of the call tx (issue
     * #131). Defaults are zero-config: when {@link #locktime} is set and
     * non-zero, sequence defaults to {@code 0xfffffffe} (non-final, so
     * consensus actually enforces nLockTime); otherwise it stays
     * {@code 0xffffffff} (final, legacy). Set explicitly only for RBF or
     * custom relative-locktime scenarios.
     */
    public final Integer sequence;

    /**
     * Cap the number of P2PKH funding inputs added to a non-terminal call tx
     * (issue #133). Funding is chosen by smallest-sufficient, largest-first
     * selection. If covering the outputs + fee would need more than this many
     * inputs, the call throws rather than silently sweeping the wallet.
     * {@code null} → no cap.
     */
    public final Integer maxFundingInputs;

    /**
     * Signer for the P2PKH funding (and terminal fee) inputs (issue #134).
     * When the funding/fee UTXOs are owned by a different key than the
     * connected method signer, set this so those inputs are signed by their
     * real owner. The method's own {@code Sig} args are still signed by the
     * connected signer. {@code null} → the connected signer (zero behaviour
     * change).
     */
    public final Signer fundingSigner;

    /**
     * A single plain P2PKH UTXO added to a terminal call tx purely to pay the
     * miner fee (issue #118). A true terminal method pays out the full
     * contract balance, so fee would be 0 and ARC rejects; the covenant
     * asserts its exact output set, so no change output can absorb a fee. The
     * fee input is added BEFORE the OP_PUSH_TX preimage is computed (so
     * hashPrevouts covers it) and is consumed entirely as fee — no change
     * output is created. Signed with {@link #fundingSigner} (falling back to
     * the connected signer). The covenant's output assertions are untouched.
     */
    public final UTXO feeUtxo;

    /**
     * Extra contract UTXOs to spend alongside {@code currentUtxo} in the same
     * transaction — the merge / swap / any multi-input covenant pattern. Each
     * one becomes an input at index {@code 1..N} (ahead of every P2PKH funding
     * input) and gets its OWN unlocking script: the same method, but with its
     * own BIP-143 preimage bound to its own outpoint, its own OP_PUSH_TX
     * signature, and its own auto-signed {@code Sig} args.
     *
     * <p>Their satoshis count as transaction input value, so a merge does not
     * need extra funding to cover the continuation. {@code null} → single
     * contract input (unchanged behaviour).
     *
     * <p>Parity: TypeScript / Go / Rust / Python / Zig / Ruby
     * {@code additionalContractInputs}.
     */
    public final List<UTXO> additionalContractInputs;

    /**
     * Per-input argument overrides for {@link #additionalContractInputs}.
     * {@code additionalContractInputArgs.get(i)} replaces the call args for
     * {@code additionalContractInputs.get(i)}; {@code null} (or a shorter list)
     * means that input reuses the primary call's args.
     *
     * <p>A merge needs this: each input's covenant sees a different
     * counterparty balance, so input 0 passes {@code otherBalance = 600} while
     * input 1 passes {@code otherBalance = 400}. {@code Sig} slots stay
     * {@code null} and are auto-signed per input.
     *
     * <p>Supplying MORE arg lists than there are additional inputs is a caller
     * mistake and throws, rather than silently dropping the extras.
     */
    public final List<List<Object>> additionalContractInputArgs;

    /**
     * Explicit continuation-satoshis override for a non-terminal stateful
     * call (TS parity: {@code options?.satoshis}). {@code null} → the
     * method's own explicit {@code this.addOutput(<sats>, ...)} (if it has
     * exactly one, with no raw output) wins, else the spent UTXO's satoshis
     * carry forward unchanged. Ignored on terminal calls, which have no
     * continuation.
     */
    public final Long satoshis;

    /**
     * Address that receives the P2PKH change output of a non-terminal call
     * (TS parity: {@code options?.changeAddress}, default the connected
     * signer's address). {@code null} → the signer's address. Honoured on the
     * stateless (non-OP_PUSH_TX) call path; the stateful / OP_PUSH_TX path
     * still sends change to the signer, because its covenant binds the change
     * output to the signer's PKH.
     */
    public final String changeAddress;

    public CallOptions(
        Map<String, Object> newState,
        List<TerminalOutput> terminalOutputs,
        List<UTXO> fundingUtxos
    ) {
        this(newState, terminalOutputs, fundingUtxos, null);
    }

    public CallOptions(
        Map<String, Object> newState,
        List<TerminalOutput> terminalOutputs,
        List<UTXO> fundingUtxos,
        Integer locktime
    ) {
        this(newState, terminalOutputs, fundingUtxos, locktime, null, null, null, null);
    }

    /** Pre-merge-support all-fields constructor; kept for source compatibility. */
    public CallOptions(
        Map<String, Object> newState,
        List<TerminalOutput> terminalOutputs,
        List<UTXO> fundingUtxos,
        Integer locktime,
        Integer sequence,
        Integer maxFundingInputs,
        Signer fundingSigner,
        UTXO feeUtxo
    ) {
        this(newState, terminalOutputs, fundingUtxos, locktime, sequence,
            maxFundingInputs, fundingSigner, feeUtxo, null, null);
    }

    /** Pre-satoshis-override all-fields constructor; kept for source compatibility. */
    public CallOptions(
        Map<String, Object> newState,
        List<TerminalOutput> terminalOutputs,
        List<UTXO> fundingUtxos,
        Integer locktime,
        Integer sequence,
        Integer maxFundingInputs,
        Signer fundingSigner,
        UTXO feeUtxo,
        List<UTXO> additionalContractInputs,
        List<List<Object>> additionalContractInputArgs
    ) {
        this(newState, terminalOutputs, fundingUtxos, locktime, sequence,
            maxFundingInputs, fundingSigner, feeUtxo, additionalContractInputs,
            additionalContractInputArgs, null);
    }

    /** Pre-changeAddress all-fields constructor; kept for source compatibility. */
    public CallOptions(
        Map<String, Object> newState,
        List<TerminalOutput> terminalOutputs,
        List<UTXO> fundingUtxos,
        Integer locktime,
        Integer sequence,
        Integer maxFundingInputs,
        Signer fundingSigner,
        UTXO feeUtxo,
        List<UTXO> additionalContractInputs,
        List<List<Object>> additionalContractInputArgs,
        Long satoshis
    ) {
        this(newState, terminalOutputs, fundingUtxos, locktime, sequence,
            maxFundingInputs, fundingSigner, feeUtxo, additionalContractInputs,
            additionalContractInputArgs, satoshis, null);
    }

    /** Canonical all-fields constructor. */
    public CallOptions(
        Map<String, Object> newState,
        List<TerminalOutput> terminalOutputs,
        List<UTXO> fundingUtxos,
        Integer locktime,
        Integer sequence,
        Integer maxFundingInputs,
        Signer fundingSigner,
        UTXO feeUtxo,
        List<UTXO> additionalContractInputs,
        List<List<Object>> additionalContractInputArgs,
        Long satoshis,
        String changeAddress
    ) {
        this.newState = newState;
        this.terminalOutputs = terminalOutputs;
        this.fundingUtxos = fundingUtxos;
        this.locktime = locktime;
        this.sequence = sequence;
        this.maxFundingInputs = maxFundingInputs;
        this.fundingSigner = fundingSigner;
        this.feeUtxo = feeUtxo;
        this.additionalContractInputs = additionalContractInputs;
        this.additionalContractInputArgs = additionalContractInputArgs;
        this.satoshis = satoshis;
        this.changeAddress = changeAddress;
    }

    /** Convenience factory for the common terminal-call case. */
    public static CallOptions terminal(List<TerminalOutput> outputs) {
        return new CallOptions(null, outputs, null);
    }

    // ------------------------------------------------------------------
    // Immutable "wither" copies for setting individual optional fields.
    // ------------------------------------------------------------------

    /** Copy with {@link #locktime} set (issue #131 companion). */
    public CallOptions withLocktime(Integer locktime) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
    }

    /** Copy with {@link #sequence} set (issue #131). */
    public CallOptions withSequence(Integer sequence) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
    }

    /** Copy with {@link #maxFundingInputs} set (issue #133). */
    public CallOptions withMaxFundingInputs(Integer maxFundingInputs) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
    }

    /** Copy with {@link #fundingSigner} set (issue #134). */
    public CallOptions withFundingSigner(Signer fundingSigner) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
    }

    /** Copy with {@link #feeUtxo} set (issue #118). */
    public CallOptions withFeeUtxo(UTXO feeUtxo) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
    }

    /** Copy with {@link #additionalContractInputs} set (merge / multi-input calls). */
    public CallOptions withAdditionalContractInputs(List<UTXO> additionalContractInputs) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
    }

    /** Copy with {@link #additionalContractInputArgs} set (merge / multi-input calls). */
    public CallOptions withAdditionalContractInputArgs(List<List<Object>> additionalContractInputArgs) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
    }

    /** Copy with {@link #satoshis} set (continuation-amount override). */
    public CallOptions withSatoshis(Long satoshis) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
    }

    /** Copy with {@link #changeAddress} set. */
    public CallOptions withChangeAddress(String changeAddress) {
        return new CallOptions(newState, terminalOutputs, fundingUtxos, locktime,
            sequence, maxFundingInputs, fundingSigner, feeUtxo,
            additionalContractInputs, additionalContractInputArgs, satoshis, changeAddress);
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
