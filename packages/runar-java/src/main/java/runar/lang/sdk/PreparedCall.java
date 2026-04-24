package runar.lang.sdk;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Deferred-signing handoff for a contract method call. Parity with the
 * Go SDK's {@code PreparedCall} (see {@code packages/runar-go/sdk_types.go}).
 *
 * <p>{@link RunarContract#prepareCall} returns one of these when a
 * caller wants to route signing through an external system (BRC-100
 * wallet, HSM, a co-signer flow, etc) rather than holding the private
 * key in-process. The public surface of {@code PreparedCall} is exactly
 * what an external signer needs:
 * <ul>
 *   <li>{@link #sighashes()} — 32-byte BIP-143 digests to be signed,
 *       one per {@code Sig} placeholder in the method's unlocking
 *       script (in the same order as {@link #sigIndices()})</li>
 *   <li>{@link #txHex()} — the prepared (unsigned-as-to-Sig-params)
 *       tx hex; useful for inspection and UI display</li>
 *   <li>{@link #sigIndices()} — positions inside the user-visible args
 *       that each sighash corresponds to (for multi-party flows)</li>
 * </ul>
 *
 * <p>The remaining fields are opaque plumbing that {@link
 * RunarContract#finalizeCall} consumes to reassemble the final
 * transaction. Callers should treat them as a black box.
 *
 * <p>Instances are immutable and safe to serialise between a coordinator
 * process and one or more external signers.
 */
public final class PreparedCall {

    // -------------------- public coordination surface --------------------
    private final String txHex;
    private final List<byte[]> sighashes;
    private final List<Integer> sigIndices;

    // -------------------- internal, consumed by finalizeCall -------------
    final String methodName;
    final List<Object> resolvedArgs;
    final UTXO contractUtxo;
    final boolean isStateful;
    final Map<String, Object> continuation;
    final String newLockingScriptHex;
    final long newSatoshis;

    PreparedCall(
        String txHex,
        List<byte[]> sighashes,
        List<Integer> sigIndices,
        String methodName,
        List<Object> resolvedArgs,
        UTXO contractUtxo,
        boolean isStateful,
        Map<String, Object> continuation,
        String newLockingScriptHex,
        long newSatoshis
    ) {
        this.txHex = txHex;
        // Deep-copy each sighash array so callers cannot mutate the
        // stored digest by poking at the returned reference.
        java.util.List<byte[]> shCopy = new java.util.ArrayList<>(sighashes.size());
        for (byte[] h : sighashes) shCopy.add(h.clone());
        this.sighashes = Collections.unmodifiableList(shCopy);
        this.sigIndices = List.copyOf(sigIndices);
        this.methodName = methodName;
        this.resolvedArgs = List.copyOf(resolvedArgs);
        this.contractUtxo = contractUtxo;
        this.isStateful = isStateful;
        this.continuation = continuation == null
            ? null
            : Collections.unmodifiableMap(new java.util.LinkedHashMap<>(continuation));
        this.newLockingScriptHex = newLockingScriptHex;
        this.newSatoshis = newSatoshis;
    }

    /** Tx hex with 72-byte zero-filled placeholders at every Sig slot. */
    public String txHex() {
        return txHex;
    }

    /**
     * Returns the BIP-143 digests the external signer(s) must sign,
     * parallel to {@link #sigIndices()}. Each array is a fresh copy;
     * mutating it does not affect this PreparedCall.
     */
    public List<byte[]> sighashes() {
        java.util.List<byte[]> out = new java.util.ArrayList<>(sighashes.size());
        for (byte[] h : sighashes) out.add(h.clone());
        return Collections.unmodifiableList(out);
    }

    /**
     * Returns the arg indices (in the method's user-visible parameter
     * list) that each sighash corresponds to. Same order as
     * {@link #sighashes()}.
     */
    public List<Integer> sigIndices() {
        return sigIndices;
    }

    /** Contract UTXO being spent. */
    public UTXO contractUtxo() {
        return contractUtxo;
    }

    /** Method name being called. */
    public String methodName() {
        return methodName;
    }

    /** {@code true} if the contract is stateful (produces a continuation output). */
    public boolean isStateful() {
        return isStateful;
    }
}
