package runar.lang.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import runar.lang.sdk.RunarArtifact.StateField;

/**
 * Wraps a compiled {@link RunarArtifact} plus a set of constructor
 * arguments, tracks contract state and the currently-owned UTXO, and
 * exposes deploy / call / state-read helpers. Parity target:
 * {@code packages/runar-go/sdk_contract.go}.
 *
 * <p>M8 scope delivers the core deploy + stateless-call flow. Stateful
 * multi-output continuations and OP_PUSHTX sighash injection ship in M9.
 */
public final class RunarContract {

    private final RunarArtifact artifact;
    private final List<Object> constructorArgs;
    private final Map<String, Object> state;
    private UTXO currentUtxo;
    private Inscription inscription;

    public RunarContract(RunarArtifact artifact, List<Object> constructorArgs) {
        this.artifact = artifact;
        int expected = artifact.abi().constructor().params().size();
        if (constructorArgs.size() != expected) {
            throw new IllegalArgumentException(
                "RunarContract: expected " + expected + " constructor args for "
                    + artifact.contractName() + ", got " + constructorArgs.size()
            );
        }
        this.constructorArgs = List.copyOf(constructorArgs);
        this.state = new HashMap<>();
        if (artifact.isStateful()) {
            for (StateField f : artifact.stateFields()) {
                if (f.initialValue() != null) {
                    state.put(f.name(), f.initialValue());
                    continue;
                }
                if (f.index() < constructorArgs.size()) {
                    state.put(f.name(), constructorArgs.get(f.index()));
                }
            }
        }
    }

    public RunarArtifact artifact() { return artifact; }

    public Map<String, Object> state() {
        return Collections.unmodifiableMap(state);
    }

    public Object state(String fieldName) {
        return state.get(fieldName);
    }

    public UTXO currentUtxo() {
        return currentUtxo;
    }

    public void setCurrentUtxo(UTXO utxo) {
        this.currentUtxo = utxo;
    }

    /** Renders the current locking script: template + constructor args + state. */
    public String lockingScript() {
        return ContractScript.renderLockingScript(artifact, constructorArgs, state, inscription);
    }

    /**
     * Attaches a 1sat ordinals inscription to this contract. The envelope
     * is spliced between the code part and the state section of the
     * locking script. Parity with Go {@code WithInscription}, Rust
     * {@code with_inscription}, and TS {@code withInscription}.
     */
    public RunarContract withInscription(Inscription insc) {
        this.inscription = insc;
        return this;
    }

    public Inscription inscription() {
        return inscription;
    }

    // ------------------------------------------------------------------
    // Deploy / Call
    // ------------------------------------------------------------------

    /**
     * Deploys the contract by signing a funding tx with the signer's
     * keys and broadcasting via {@code provider}. Tracks the resulting
     * contract UTXO on this instance.
     */
    public DeployOutcome deploy(Provider provider, Signer signer, long satoshis, String changeAddress) {
        String lockingScript = lockingScript();
        TransactionBuilder.DeployResult r = TransactionBuilder.buildDeployWithLockingScript(
            lockingScript, provider, signer, satoshis, changeAddress
        );
        String txid = provider.broadcastRaw(r.txHex());
        this.currentUtxo = new UTXO(txid, 0, satoshis, lockingScript);
        return new DeployOutcome(txid, r.txHex(), currentUtxo);
    }

    public DeployOutcome deploy(Provider provider, Signer signer, long satoshis) {
        return deploy(provider, signer, satoshis, null);
    }

    public record DeployOutcome(String txid, String rawTxHex, UTXO deployedUtxo) {}

    /**
     * Calls {@code method} with {@code args}. Stateless contracts are
     * fully consumed; stateful contracts produce a continuation output
     * with updated state.
     *
     * <p>The method selector and argument pushes are built here; the
     * Sig param (auto-computed) is replaced with a real signature over
     * the BIP-143 sighash of the constructed transaction.
     */
    public CallOutcome call(
        String methodName,
        List<Object> args,
        Map<String, Object> stateUpdates,
        Provider provider,
        Signer signer
    ) {
        if (currentUtxo == null) {
            throw new IllegalStateException(
                "RunarContract.call: contract has not been deployed. Call deploy() or setCurrentUtxo()."
            );
        }
        RunarArtifact.ABIMethod m = findMethod(methodName);
        if (m == null) {
            throw new IllegalArgumentException(
                "RunarContract.call: method '" + methodName + "' not found in " + artifact.contractName()
            );
        }

        // Merge state updates ahead of building the new locking script.
        if (artifact.isStateful() && stateUpdates != null) {
            state.putAll(stateUpdates);
        }

        // Build an unlocking script. For stateless calls it is just the
        // user args + optional method-selector push. Sig params inside
        // `args` that are null get replaced with a real signature after
        // sighash computation.
        int sigIndex = -1;
        List<Object> resolved = new ArrayList<>(args);
        for (int i = 0; i < m.params().size() && i < resolved.size(); i++) {
            if ("Sig".equals(m.params().get(i).type()) && resolved.get(i) == null) {
                sigIndex = i;
                resolved.set(i, "00".repeat(72)); // 72-byte placeholder
            }
            if ("PubKey".equals(m.params().get(i).type()) && resolved.get(i) == null) {
                resolved.set(i, ScriptUtils.bytesToHex(signer.pubKey()));
            }
        }

        String unlockHex = buildUnlockingScript(m, resolved);
        Map<String, Object> continuation = artifact.isStateful() ? state : null;
        long newSats = artifact.isStateful() ? currentUtxo.satoshis() : 0;

        TransactionBuilder.CallResult result = TransactionBuilder.buildCallTransaction(
            artifact, currentUtxo, unlockHex, continuation, newSats, provider, signer, null
        );
        String txHex = result.txHex();

        // If a Sig placeholder was present, re-sign and splice the real sig in.
        if (sigIndex >= 0) {
            byte[] sighash = computeContractSighash(txHex, 0);
            byte[] der = signer.sign(sighash, null);
            String sigHex = ScriptUtils.bytesToHex(der)
                + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
            resolved.set(sigIndex, sigHex);
            unlockHex = buildUnlockingScript(m, resolved);
            // Rebuild with final unlocking script.
            result = TransactionBuilder.buildCallTransaction(
                artifact, currentUtxo, unlockHex, continuation, newSats, provider, signer, null
            );
            txHex = result.txHex();
        }

        String txid = provider.broadcastRaw(txHex);
        UTXO nextUtxo = null;
        if (artifact.isStateful() && result.newLockingScriptHex() != null) {
            nextUtxo = new UTXO(txid, 0, newSats, result.newLockingScriptHex());
            this.currentUtxo = nextUtxo;
        } else {
            this.currentUtxo = null;
        }
        return new CallOutcome(txid, txHex, nextUtxo);
    }

    public record CallOutcome(String txid, String rawTxHex, UTXO nextContractUtxo) {}

    // ------------------------------------------------------------------
    // Multi-signer API (prepareCall / finalizeCall)
    // ------------------------------------------------------------------

    /**
     * Prepares a call for external signing. Mirrors the Go SDK's
     * {@code PrepareCall} and the TS SDK's {@code prepareCall()}.
     *
     * <p>Unlike {@link #call}, this does <em>not</em> sign and does not
     * broadcast. The caller receives a {@link PreparedCall} containing
     * the tx hex (with 72-byte zero placeholders in every {@code Sig}
     * slot) and one BIP-143 sighash per placeholder. External signer(s)
     * sign each digest out-of-band and hand the DER signatures back to
     * {@link #finalizeCall(PreparedCall, java.util.List, Provider)}.
     *
     * <p>{@code null} entries in {@code args} are treated as auto-compute
     * slots:
     * <ul>
     *   <li>{@code Sig} — replaced with a 72-byte zero placeholder; the
     *       sighash for this slot is added to
     *       {@link PreparedCall#sighashes()}</li>
     *   <li>{@code PubKey} — if a {@code signer} is provided, replaced
     *       with its compressed pubkey; otherwise the caller must
     *       supply the pubkey explicitly</li>
     * </ul>
     *
     * @param signer optional signer used to fill in auto-compute PubKey
     *               slots. Pass {@code null} if the caller is supplying
     *               every non-{@code Sig} arg up front (e.g. a pure
     *               remote-signing flow).
     */
    public PreparedCall prepareCall(
        String methodName,
        List<Object> args,
        Map<String, Object> stateUpdates,
        Provider provider,
        Signer signer
    ) {
        if (currentUtxo == null) {
            throw new IllegalStateException(
                "RunarContract.prepareCall: contract has not been deployed. Call deploy() or setCurrentUtxo()."
            );
        }
        RunarArtifact.ABIMethod m = findMethod(methodName);
        if (m == null) {
            throw new IllegalArgumentException(
                "RunarContract.prepareCall: method '" + methodName + "' not found in " + artifact.contractName()
            );
        }

        // Snapshot state + apply pending updates so the prepared tx
        // reflects the continuation the caller expects.
        if (artifact.isStateful() && stateUpdates != null) {
            state.putAll(stateUpdates);
        }

        List<Integer> sigIndices = new ArrayList<>();
        List<Object> resolved = new ArrayList<>(args);
        for (int i = 0; i < m.params().size() && i < resolved.size(); i++) {
            String type = m.params().get(i).type();
            if ("Sig".equals(type) && resolved.get(i) == null) {
                sigIndices.add(i);
                resolved.set(i, "00".repeat(72));
            }
            if ("PubKey".equals(type) && resolved.get(i) == null && signer != null) {
                resolved.set(i, ScriptUtils.bytesToHex(signer.pubKey()));
            }
        }

        String unlockHex = buildUnlockingScript(m, resolved);
        Map<String, Object> continuation = artifact.isStateful() ? new java.util.LinkedHashMap<>(state) : null;
        long newSats = artifact.isStateful() ? currentUtxo.satoshis() : 0;

        TransactionBuilder.CallResult result = TransactionBuilder.buildCallTransaction(
            artifact, currentUtxo, unlockHex, continuation, newSats, provider, signer, null
        );
        String txHex = result.txHex();

        // BIP-143 is invariant under scriptSig contents (it hashes the
        // subscript — i.e. the locking script — not the unlocking
        // script of the input being signed). Since every Sig
        // placeholder is the same 72 bytes and sits in the same input,
        // each signer gets the *same* sighash to sign. That mirrors the
        // BSV stateless-contract multisig pattern used by the other
        // SDKs.
        byte[] sighash = new byte[0];
        if (!sigIndices.isEmpty()) {
            sighash = computeContractSighash(txHex, 0);
        }
        List<byte[]> sighashes = new ArrayList<>(sigIndices.size());
        for (int i = 0; i < sigIndices.size(); i++) sighashes.add(sighash);

        return new PreparedCall(
            txHex,
            sighashes,
            sigIndices,
            methodName,
            resolved,
            currentUtxo,
            artifact.isStateful(),
            continuation,
            result.newLockingScriptHex(),
            newSats
        );
    }

    public PreparedCall prepareCall(
        String methodName,
        List<Object> args,
        Provider provider,
        Signer signer
    ) {
        return prepareCall(methodName, args, null, provider, signer);
    }

    public PreparedCall prepareCall(
        String methodName,
        List<Object> args,
        Provider provider
    ) {
        return prepareCall(methodName, args, null, provider, null);
    }

    /**
     * Finalises a {@link PreparedCall} by splicing external signatures
     * into the unlocking script and broadcasting. Mirrors the Go SDK's
     * {@code FinalizeCall}.
     *
     * <p>{@code signatures} must contain one DER-encoded ECDSA
     * signature per entry in {@link PreparedCall#sigIndices()}, in the
     * same order. The SDK appends the standard {@code SIGHASH_ALL |
     * FORKID} flag byte before the signature lands in the unlocking
     * script.
     *
     * @throws IllegalArgumentException if {@code signatures.size()} does
     *         not match {@code prepared.sigIndices().size()} or any
     *         signature is empty / malformed (does not start with
     *         0x30 DER tag).
     */
    public CallOutcome finalizeCall(
        PreparedCall prepared,
        List<byte[]> signatures,
        Provider provider
    ) {
        if (prepared == null) {
            throw new IllegalArgumentException("RunarContract.finalizeCall: prepared is null");
        }
        if (signatures == null) {
            throw new IllegalArgumentException("RunarContract.finalizeCall: signatures is null");
        }
        if (signatures.size() != prepared.sigIndices().size()) {
            throw new IllegalArgumentException(
                "RunarContract.finalizeCall: expected " + prepared.sigIndices().size()
                    + " signatures, got " + signatures.size()
            );
        }
        for (byte[] sig : signatures) {
            if (sig == null || sig.length < 2 || (sig[0] & 0xff) != 0x30) {
                throw new IllegalArgumentException(
                    "RunarContract.finalizeCall: signature is not a DER sequence (must start with 0x30)"
                );
            }
        }

        RunarArtifact.ABIMethod m = findMethod(prepared.methodName);
        if (m == null) {
            throw new IllegalArgumentException(
                "RunarContract.finalizeCall: method '" + prepared.methodName
                    + "' not found in " + artifact.contractName()
            );
        }

        // Splice real signatures into the resolved-args list.
        List<Object> resolved = new ArrayList<>(prepared.resolvedArgs);
        for (int i = 0; i < prepared.sigIndices().size(); i++) {
            int argIdx = prepared.sigIndices().get(i);
            byte[] der = signatures.get(i);
            String sigHex = ScriptUtils.bytesToHex(der)
                + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
            resolved.set(argIdx, sigHex);
        }
        String unlockHex = buildUnlockingScript(m, resolved);

        // Rebuild the tx with the real unlocking script. The outputs
        // (and therefore BIP-143 sighash inputs) are identical to the
        // prepared tx, so the spliced signatures remain valid.
        RawTx tx = RawTxParser.parse(prepared.txHex());
        tx.setUnlockingScript(0, unlockHex);
        String finalHex = tx.toHex();

        String txid = provider.broadcastRaw(finalHex);
        UTXO nextUtxo = null;
        if (prepared.isStateful && prepared.newLockingScriptHex != null) {
            nextUtxo = new UTXO(txid, 0, prepared.newSatoshis, prepared.newLockingScriptHex);
            this.currentUtxo = nextUtxo;
        } else {
            this.currentUtxo = null;
        }
        return new CallOutcome(txid, finalHex, nextUtxo);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private RunarArtifact.ABIMethod findMethod(String name) {
        for (RunarArtifact.ABIMethod m : artifact.abi().methods()) {
            if (m.name().equals(name)) return m;
        }
        return null;
    }

    private String buildUnlockingScript(RunarArtifact.ABIMethod m, List<Object> args) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < args.size(); i++) {
            Object arg = args.get(i);
            String type = i < m.params().size() ? m.params().get(i).type() : "ByteString";
            sb.append(ContractScript.encodeConstructorArg(arg, type));
        }
        return sb.toString();
    }

    /** Computes the BIP-143 sighash over the first input of a rendered tx. */
    private byte[] computeContractSighash(String txHex, int inputIndex) {
        RawTx parsed = RawTxParser.parse(txHex);
        return parsed.sighashBIP143(inputIndex, currentUtxo.scriptHex(), currentUtxo.satoshis(),
            RawTx.SIGHASH_ALL_FORKID);
    }
}
