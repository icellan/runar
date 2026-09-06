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

    /**
     * Producer-side marker (issue #106) for the deliberately-empty branch of an
     * OR-CHECKSIG method — {@code checkSig(sigA, pkA) || checkSig(sigB, pkB)},
     * where {@code ||} lowers to the non-lazy {@code OP_BOOLOR} so BOTH
     * {@code OP_CHECKSIG}s run. Only the matching branch supplies a real
     * signature; the failing branch MUST push an empty signature (OP_0) or
     * BIP146 NULLFAIL rejects the whole spend.
     *
     * <p>Pass {@code EMPTY_SIG} as the call arg for the non-matching {@code Sig}
     * slot: the SDK pushes OP_0 for it and never signs it — distinct from
     * {@code null} (auto-sign) and an explicit hex-bytes value. Coexists with
     * {@code null} at the same call: {@code call("execute", List.of(NULL,
     * EMPTY_SIG))} signs only slot 0. ({@code null} entries must be added to the
     * arg list explicitly, e.g. via a mutable list.)
     */
    public static final Object EMPTY_SIG = new Object();

    /** Type guard: is this call arg the {@link #EMPTY_SIG} marker (issue #106)? */
    public static boolean isEmptySig(Object value) {
        return value == EMPTY_SIG;
    }

    private final RunarArtifact artifact;
    private final List<Object> constructorArgs;
    private final Map<String, Object> state;
    private UTXO currentUtxo;
    private Inscription inscription;
    /**
     * Witness values for intent-covenant intrinsic auto-injected params.
     * {@code _prevOutScript_<i>} values are stored per-input-index in
     * {@code prevOutScripts}; {@code _serialisedOutputs} is stored in
     * {@code serialisedOutputs}. Both are lowercase hex strings (normalized
     * in the setters). Read by the call-builder when assembling the
     * unlocking script for methods that use {@code extractPrevOutputScript}
     * / {@code requireOutputP2PKH}.
     */
    private final Map<Integer, String> prevOutScripts = new HashMap<>();
    private String serialisedOutputs;

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

    /**
     * Internal constructor used by {@link #fromUtxo} / {@link #fromTxId}
     * to re-attach to an existing on-chain UTXO.
     *
     * <p>Issue #119: the constructor args are recovered from the deployed
     * locking script via {@link ContractScript#extractConstructorArgs} rather
     * than left empty. Restored stateful spends feed readonly ctor params into
     * the ANF interpreter's state-continuation formula, so a placeholder
     * (empty / zero) arg list computed the wrong new state and left the spend
     * unspendable. Params without a constructor slot (mutable state fields)
     * fall back to 0 and are overwritten by {@link StateSerializer} below.
     */
    private RunarContract(RunarArtifact artifact, UTXO utxo) {
        this.artifact = artifact;
        this.constructorArgs = List.copyOf(
            ContractScript.extractConstructorArgs(artifact, utxo.scriptHex()));
        this.state = new HashMap<>();
        this.currentUtxo = utxo;
        if (artifact.isStateful()) {
            // Re-extract state from the on-chain locking script so subsequent
            // call() invocations see the same state the chain has.
            Map<String, Object> extracted =
                StateSerializer.extractFromScript(artifact, utxo.scriptHex());
            if (extracted != null) state.putAll(extracted);
        }
    }

    /**
     * Re-attaches a {@link RunarContract} to an existing on-chain UTXO.
     * Mirrors the Ruby/Go/TS/Rust/Python {@code from_utxo} factories.
     *
     * <p>For stateful contracts, state is reconstructed from the UTXO's
     * locking script via {@link StateSerializer#extractFromScript}.
     * Constructor args are not re-run — they were already baked into
     * the locking script at deploy time.
     */
    public static RunarContract fromUtxo(RunarArtifact artifact, UTXO utxo) {
        if (artifact == null) throw new IllegalArgumentException("artifact is null");
        if (utxo == null) throw new IllegalArgumentException("utxo is null");
        return new RunarContract(artifact, utxo);
    }

    /**
     * Re-attaches a {@link RunarContract} by fetching the UTXO via
     * {@code provider}. Throws {@link IllegalArgumentException} if the
     * provider does not know the outpoint. Mirrors Ruby/Go/TS/Rust/Python
     * {@code from_txid} / {@code fromTxId}.
     */
    public static RunarContract fromTxId(
        RunarArtifact artifact,
        String txid,
        int outputIndex,
        Provider provider
    ) {
        if (provider == null) throw new IllegalArgumentException("provider is null");
        UTXO utxo = provider.getUtxo(txid, outputIndex);
        if (utxo == null) {
            throw new IllegalArgumentException(
                "RunarContract.fromTxId: UTXO not found at " + txid + ":" + outputIndex
            );
        }
        return fromUtxo(artifact, utxo);
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
    // Intent-intrinsic witness values
    // ------------------------------------------------------------------

    /**
     * Supply the prev-output locking-script witness for input
     * {@code inputIndex}. Required for methods that call
     * {@code extractPrevOutputScript(inputIndex)}, which the compiler lowers
     * into an auto-injected {@code _prevOutScript_<inputIndex>} ABI param.
     *
     * @param inputIndex literal input index passed to {@code extractPrevOutputScript}
     * @param bytesHex   hex string (with or without {@code 0x} prefix, any casing)
     */
    public void setPrevOutScript(int inputIndex, String bytesHex) {
        prevOutScripts.put(inputIndex, normalizeWitnessHex(bytesHex));
    }

    /** {@code byte[]}-input convenience overload of {@link #setPrevOutScript}. */
    public void setPrevOutScript(int inputIndex, byte[] bytes) {
        prevOutScripts.put(inputIndex, ScriptUtils.bytesToHex(bytes));
    }

    /**
     * Supply the serialised-outputs witness for the current call. Required
     * for methods that call {@code requireOutputP2PKH(...)}, which the
     * compiler lowers into an auto-injected {@code _serialisedOutputs} ABI
     * param.
     */
    public void setSerialisedOutputs(String bytesHex) {
        this.serialisedOutputs = normalizeWitnessHex(bytesHex);
    }

    /** {@code byte[]}-input convenience overload of {@link #setSerialisedOutputs}. */
    public void setSerialisedOutputs(byte[] bytes) {
        this.serialisedOutputs = ScriptUtils.bytesToHex(bytes);
    }

    /**
     * Build the trailing intent-intrinsic witness hex for {@code method},
     * in ABI order ({@code _prevOutScript_*} first, then
     * {@code _serialisedOutputs}). Each value is pushed via PUSHDATA so that
     * the on-chain method body's {@code load_param} lifts the exact bytes
     * the caller set.
     *
     * @throws WitnessValueMissingError for any auto-injected param the caller
     *     hasn't supplied via {@link #setPrevOutScript} /
     *     {@link #setSerialisedOutputs}.
     */
    private String buildIntentWitnessHex(RunarArtifact.ABIMethod method) {
        StringBuilder sb = new StringBuilder();
        for (RunarArtifact.ABIParam p : method.params()) {
            String n = p.name();
            if (n.startsWith("_prevOutScript_")) {
                String idxStr = n.substring("_prevOutScript_".length());
                int idx;
                try {
                    idx = Integer.parseInt(idxStr);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("malformed auto-injected param name '" + n + "'", e);
                }
                String val = prevOutScripts.get(idx);
                if (val == null) {
                    throw new WitnessValueMissingError(n, method.name(), artifact.contractName());
                }
                sb.append(ScriptUtils.encodePushData(val));
            } else if ("_serialisedOutputs".equals(n)) {
                if (serialisedOutputs == null) {
                    throw new WitnessValueMissingError(n, method.name(), artifact.contractName());
                }
                sb.append(ScriptUtils.encodePushData(serialisedOutputs));
            }
        }
        return sb.toString();
    }

    /**
     * Normalize a witness-value hex string (optional {@code 0x} prefix,
     * any casing) into a lowercase hex string suitable for PUSHDATA.
     * Throws {@link IllegalArgumentException} on odd-length / non-hex inputs.
     */
    private static String normalizeWitnessHex(String s) {
        if (s == null) throw new IllegalArgumentException("witness value: null");
        String h = s;
        if (h.startsWith("0x") || h.startsWith("0X")) h = h.substring(2);
        if ((h.length() & 1) != 0) {
            throw new IllegalArgumentException(
                "witness value: hex string must have even length (got " + h.length() + ")");
        }
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) throw new IllegalArgumentException("witness value: invalid hex characters");
        }
        return h.toLowerCase(java.util.Locale.ROOT);
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
        // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        ScriptSizeExceededError.assertScriptHexUnderLimit(
            lockingScript, InputLimits.MAX_SCRIPT_BYTES,
            artifact.contractName() + ".deploy"
        );
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

    /**
     * Rich-options deploy overload. Mirrors the TS SDK's
     * {@code deploy(provider, signer, options)}: {@link DeployOptions#satoshis}
     * (default 1) and {@link DeployOptions#changeAddress} (default the deploy
     * signer's address) configure the contract output + change, while
     * {@link DeployOptions#fundingSigner} (issue #134) signs the P2PKH funding
     * inputs when they are owned by a different key than the deploy signer.
     * When {@code fundingSigner} is unset the deploy signer signs them (zero
     * behaviour change vs the positional overloads).
     */
    public DeployOutcome deploy(Provider provider, Signer signer, DeployOptions options) {
        long satoshis = (options != null && options.satoshis != null) ? options.satoshis : 1L;
        String changeAddress = options != null ? options.changeAddress : null;
        Signer fundingSigner = (options != null && options.fundingSigner != null)
            ? options.fundingSigner : signer;

        String lockingScript = lockingScript();
        // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        ScriptSizeExceededError.assertScriptHexUnderLimit(
            lockingScript, InputLimits.MAX_SCRIPT_BYTES,
            artifact.contractName() + ".deploy"
        );
        TransactionBuilder.DeployResult r = TransactionBuilder.buildDeployWithLockingScript(
            lockingScript, provider, signer, satoshis, changeAddress, fundingSigner
        );
        String txid = provider.broadcastRaw(r.txHex());
        this.currentUtxo = new UTXO(txid, 0, satoshis, lockingScript);
        return new DeployOutcome(txid, r.txHex(), currentUtxo);
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
        return callWithOptions(
            methodName,
            args,
            stateUpdates == null ? null : new CallOptions(stateUpdates, null, null),
            provider,
            signer
        );
    }

    /**
     * Rich-options overload that supports terminal output spending and
     * caller-supplied funding UTXOs in addition to state overrides. See
     * {@link CallOptions} for field semantics. Distinct method name from
     * {@link #call(String, List, Map, Provider, Signer)} so callers
     * passing {@code null} for the third arg don't trigger overload
     * ambiguity.
     */
    public CallOutcome callWithOptions(
        String methodName,
        List<Object> args,
        CallOptions options,
        Provider provider,
        Signer signer
    ) {
        if (currentUtxo == null) {
            throw new IllegalStateException(
                "RunarContract.call: contract has not been deployed. Call deploy() or setCurrentUtxo()."
            );
        }
        // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        ScriptSizeExceededError.assertScriptHexUnderLimit(
            currentUtxo.scriptHex(), InputLimits.MAX_SCRIPT_BYTES,
            artifact.contractName() + ".call(" + methodName + ")"
        );
        RunarArtifact.ABIMethod m = findMethod(methodName);
        if (m == null) {
            throw new IllegalArgumentException(
                "RunarContract.call: method '" + methodName + "' not found in " + artifact.contractName()
            );
        }

        boolean isStateful = artifact.isStateful();
        // parentStateful gates ONLY the issue-#42/#44 terminal sighash subscript
        // trim (the OP_PUSH_TX / codesep-aware path). A StatefulSmartContract
        // with zero mutable fields has empty stateFields yet still injects
        // checkPreimage at method entry, so its user checkSig runs after the
        // OP_CODESEPARATOR and must sign the trimmed subscript. parentClass is
        // the authoritative signal; falls back to isStateful for older artifacts.
        boolean parentStateful = artifact.parentStateful();

        // Identify the "user" params — every formal param except those the
        // compiler injects implicitly for stateful contracts. The args list
        // the caller passes only addresses user params; implicit ones are
        // filled in by the SDK.
        List<RunarArtifact.ABIParam> userParams = userParams(m, isStateful);
        if (userParams.size() != args.size()) {
            throw new IllegalArgumentException(
                "RunarContract.call: method '" + methodName + "' expects "
                    + userParams.size() + " user args, got " + args.size()
            );
        }

        Map<String, Object> stateUpdates = options == null ? null : options.newState;
        List<CallOptions.TerminalOutput> terminalOutputs =
            options == null ? null : options.terminalOutputs;
        List<UTXO> fundingUtxos =
            options == null || options.fundingUtxos == null ? List.of() : options.fundingUtxos;

        // Auto-merge state updates: explicit caller-supplied stateUpdates
        // win; otherwise the ANF interpreter computes the new state and
        // any addDataOutput entries from the contract body. Mirrors the
        // Go/Python SDKs. Skip ANF auto-compute for terminal calls — the
        // contract is fully spent so there's no continuation to update.
        List<TransactionBuilder.DataOutput> resolvedDataOutputs = new ArrayList<>();
        // State-class outputs (state continuation + raw) in source order from
        // the ANF interpreter (finding G1). Empty for methods that emit no
        // this.addRawOutput(...) — the raw-output branch in callWithPushTx is a
        // no-op in that case, so the common path is byte-for-byte unchanged.
        List<AnfInterpreter.OrderedOutput> orderedOutputs = new ArrayList<>();
        if (isStateful && terminalOutputs == null) {
            // Run the interpreter even when the caller supplied explicit state.
            // It produces TWO different things: the new state VALUES, and the
            // output SHAPE (how many outputs, their satoshis, any data outputs).
            // `stateUpdates` overrides only the former. Short-circuiting on it
            // used to discard the latter too, so a method with an explicit
            // `this.addOutput(<sats>, ...)` silently fell back to the spent
            // input's value — the continuation was built at the wrong amount,
            // the covenant's hashOutputs binding rejected the spend, and the
            // funds were stranded. That is exactly how the on-chain merge test
            // failed: state correct, continuation at 5000 instead of 4000.
            if (artifact.anf() != null) {
                Map<String, Object> namedArgs = buildNamedArgs(userParams, args);
                try {
                    AnfInterpreter.ExecutionResult execResult = AnfInterpreter.computeNewStateAndDataOutputs(
                        artifact.anf(), methodName, state, namedArgs, constructorArgs
                    );
                    // Caller-supplied state wins; the interpreter's is the
                    // fallback. The output shape below is taken either way.
                    if (stateUpdates == null) state.putAll(execResult.newState);
                    for (AnfInterpreter.DataOutput d : execResult.dataOutputs) {
                        resolvedDataOutputs.add(
                            new TransactionBuilder.DataOutput(d.satoshis(), d.script())
                        );
                    }
                    orderedOutputs = new ArrayList<>(execResult.outputs);
                } catch (RuntimeException err) {
                    // FAIL CLOSED (NEW-006). The legacy behaviour was to
                    // swallow this and build the continuation from the CURRENT
                    // (pre-call) state, which the covenant's hashOutputs
                    // binding then rejects — a silent "your call cannot be
                    // broadcast", plus silent loss of the method's data / raw
                    // outputs. The interpreter is the only thing that knows
                    // this method's post-state AND its addDataOutput /
                    // addRawOutput payloads, so there is nothing to fall back
                    // TO: an explicit `newState` covers only the state field
                    // and still leaves the outputs missing.
                    throw new IllegalStateException(
                        "RunarContract.call('" + methodName + "'): the ANF interpreter could not"
                            + " evaluate the method body, so the state continuation and data"
                            + " outputs this call would commit cannot be derived. Refusing to"
                            + " broadcast a transaction built from the pre-call state. Cause: "
                            + err.getMessage(),
                        err
                    );
                }
            }
            // Explicit state always applies, including when there is no ANF to
            // interpret or the interpreter could not run the body.
            if (stateUpdates != null) {
                state.putAll(stateUpdates);
            }
        }

        // Resolve user args: replace nulls per ABI type. Track every Sig
        // placeholder so we can sign each one after the tx layout settles.
        List<Object> resolved = new ArrayList<>(args);
        List<Integer> sigIndices = new ArrayList<>();
        for (int i = 0; i < userParams.size(); i++) {
            String type = userParams.get(i).type();
            if ("Sig".equals(type) && resolved.get(i) == null) {
                sigIndices.add(i);
                resolved.set(i, "00".repeat(72));
            } else if ("PubKey".equals(type) && resolved.get(i) == null) {
                resolved.set(i, ScriptUtils.bytesToHex(signer.pubKey()));
            } else if (isAutoPrevoutsParam(userParams.get(i), resolved.get(i))) {
                // `allPrevouts` is the documented auto-compute slot: the covenant
                // hashes every input's outpoint, so its value only exists once the
                // tx layout is known. Stand in with the right LENGTH (36 bytes per
                // input) so the fee is sized correctly, then fill it in for real
                // after layout. Gate on the parameter NAME, not just the type —
                // finding G6: a type-blind stub silently spliced outpoint bytes
                // into an ordinary null ByteString param.
                int estimatedInputs = 1 + extraContractInputCount(options) + 1;
                resolved.set(i, "00".repeat(36 * estimatedInputs));
            } else {
                rejectUnresolvableNullArg(
                    "RunarContract.call", userParams.get(i), i, resolved.get(i));
            }
        }

        // Detect injected param shapes: stateful contracts may carry
        // _changePKH / _changeAmount / _newAmount and an OP_PUSH_TX
        // preimage slot. The compiler emits these in a fixed order:
        // [user params...] [_changePKH] [_changeAmount] [_newAmount] [txPreimage].
        boolean methodNeedsChange = hasParam(m, "_changePKH");
        boolean methodNeedsNewAmount = hasParam(m, "_newAmount");
        // parentStateful pulls a zero-mutable-field StatefulSmartContract into
        // the OP_PUSH_TX / codesep-aware path so its user checkSig signs the
        // trimmed subscript (issue #44). stateful+ txPreimage covers the rest.
        boolean needsOpPushTx = parentStateful || isStateful || hasParam(m, "txPreimage");

        // ------------------------------------------------------------
        // Terminal call: contract fully spent into caller-supplied
        // outputs, no continuation, no automatic change. Bypasses both
        // legacy paths and routes to the dedicated terminal builder.
        // ------------------------------------------------------------
        // Only the OP_PUSH_TX path below can bind an extra contract input to its
        // own preimage. The terminal and legacy-stateless builders lay out a
        // single contract input, so accepting the option there would silently
        // drop the extra UTXOs — the tx would spend less than the caller asked
        // and the merge would look like it succeeded. Fail loudly instead.
        if (extraContractInputCount(options) > 0 && (terminalOutputs != null || !needsOpPushTx)) {
            throw new IllegalArgumentException(
                "RunarContract.call(" + methodName + "): additionalContractInputs is only "
                    + "supported on the OP_PUSH_TX call path. "
                    + (terminalOutputs != null
                        ? "Terminal calls spend the contract into a caller-supplied output set "
                          + "and take a single contract input."
                        : "This method has no txPreimage parameter, so each extra input has no "
                          + "covenant to bind it."));
        }

        if (terminalOutputs != null) {
            int terminalLocktime = (options != null && options.locktime != null)
                ? options.locktime : 0;
            return callTerminal(
                m, methodName, resolved, sigIndices,
                methodNeedsChange, methodNeedsNewAmount,
                isStateful, parentStateful, terminalOutputs, fundingUtxos, provider, signer,
                terminalLocktime, options
            );
        }

        // ------------------------------------------------------------
        // Stateless single-method contract: thin path (legacy P2PKH).
        // ------------------------------------------------------------
        if (!isStateful && !needsOpPushTx) {
            return callStateless(m, resolved, sigIndices, provider, signer);
        }

        // ------------------------------------------------------------
        // Stateful (or stateless+OP_PUSH_TX) contract: full flow with
        // funding inputs, OP_PUSH_TX prefix, preimage push, method
        // selector.
        // ------------------------------------------------------------
        int pushTxLocktime = (options != null && options.locktime != null)
            ? options.locktime : 0;
        return callWithPushTx(
            m, methodName, resolved, sigIndices,
            methodNeedsChange, methodNeedsNewAmount,
            isStateful, parentStateful, resolvedDataOutputs, orderedOutputs, provider, signer, pushTxLocktime,
            options
        );
    }

    /**
     * Stateless single-method legacy path. Builds a tx that fully
     * consumes the contract UTXO, signs every Sig placeholder against
     * the contract's BIP-143 sighash, and broadcasts. Matches the
     * pre-OP_PUSH_TX behavior for simple P2PKH-style contracts.
     */
    private CallOutcome callStateless(
        RunarArtifact.ABIMethod m,
        List<Object> resolved,
        List<Integer> sigIndices,
        Provider provider,
        Signer signer
    ) {
        // Pre-resolve intent-intrinsic witness hex (throws
        // WitnessValueMissingError if any auto-injected param wasn't set).
        String intentWitnessHex = buildIntentWitnessHex(m);
        String unlockHex = buildUnlockingScript(m, resolved) + intentWitnessHex;

        TransactionBuilder.CallResult result = TransactionBuilder.buildCallTransaction(
            artifact, currentUtxo, unlockHex, null, 0, provider, signer, null
        );
        String txHex = result.txHex();

        if (!sigIndices.isEmpty()) {
            // Issue #123: sign under the method's declared @sighash mode (default 0x41).
            int methodSigHash = m.sigHashType() != null ? m.sigHashType() : RawTx.SIGHASH_ALL_FORKID;
            byte[] sighash = computeContractSighash(txHex, 0, methodSigHash);
            for (int idx : sigIndices) {
                byte[] der = signer.sign(sighash, null);
                String sigHex = ScriptUtils.bytesToHex(der)
                    + String.format("%02x", methodSigHash & 0xff);
                resolved.set(idx, sigHex);
            }
            unlockHex = buildUnlockingScript(m, resolved) + intentWitnessHex;
            result = TransactionBuilder.buildCallTransaction(
                artifact, currentUtxo, unlockHex, null, 0, provider, signer, null
            );
            txHex = result.txHex();
        }

        String txid = provider.broadcastRaw(txHex);
        this.currentUtxo = null;
        return new CallOutcome(txid, txHex, null);
    }

    /**
     * Full OP_PUSH_TX call flow: spawns a stateful continuation output
     * (when applicable), borrows P2PKH UTXOs from the signer's address
     * to pay the fee, splices the {@code preimage} into the unlocking
     * script, and broadcasts. (BUG-100 fix: no OP_PUSH_TX signature is
     * pushed — it is derived on-chain from the preimage.)
     */
    private CallOutcome callWithPushTx(
        RunarArtifact.ABIMethod m,
        String methodName,
        List<Object> resolved,
        List<Integer> sigIndices,
        boolean methodNeedsChange,
        boolean methodNeedsNewAmount,
        boolean isStateful,
        boolean parentStateful,
        List<TransactionBuilder.DataOutput> dataOutputs,
        List<AnfInterpreter.OrderedOutput> orderedOutputs,
        Provider provider,
        Signer signer,
        int locktime,
        CallOptions options
    ) {
        // Funding inputs are signed by fundingSigner when set (issue #134): the
        // method signer may not own the funding coins. Defaults to the connected
        // signer (zero behaviour change). The method's own Sig args keep the
        // connected signer.
        Signer fundingSigner = (options != null && options.fundingSigner != null)
            ? options.fundingSigner : signer;
        Integer optSequence = options != null ? options.sequence : null;
        Integer optLocktime = options != null ? options.locktime : null;
        Integer maxFundingInputs = options != null ? options.maxFundingInputs : null;

        // Pre-resolve intent-intrinsic witness hex. Throws
        // WitnessValueMissingError if a `_prevOutScript_<i>` or
        // `_serialisedOutputs` param wasn't set on the contract — raised
        // BEFORE any signing / broadcast work, mirroring other entry guards.
        String intentWitnessHex = buildIntentWitnessHex(m);

        // Continuation output (stateful contracts).
        String newLockingScript = null;
        long newSats = 0;
        if (isStateful) {
            String codePart = ContractScript.extractCodePart(currentUtxo.scriptHex());
            String stateHex = StateSerializer.serialize(artifact.stateFields(), state);
            newLockingScript = codePart + "6a" + stateHex;
            // Honor an explicit this.addOutput(<sats>, ...) state continuation: the
            // ANF interpreter records that amount in orderedOutputs (one "state"
            // entry per addOutput). A method with a single explicit addOutput and no
            // raw output must build its continuation at that amount, not default to
            // the spent input's value — otherwise the covenant's hashOutputs binding
            // rejects the spend and funds are stranded. Finding G1 (raw-output branch
            // below) reads the same satoshis; this generalizes it to the no-raw
            // single-continuation path. With no explicit addOutput (the auto-injected
            // continuation) orderedOutputs is empty and the input-value default holds.
            long stateEntryCount = orderedOutputs.stream()
                .filter(o -> "state".equals(o.kind())).count();
            newSats = (orderedOutputs.size() == 1 && stateEntryCount == 1)
                ? orderedOutputs.get(0).satoshis()
                : currentUtxo.satoshis();
        }

        // Finding G1: a method that calls this.addRawOutput(...) folds the raw
        // output(s) into the covenant's continuation hashOutputs IN SOURCE
        // ORDER, interleaved with the state continuation this.addOutput(...).
        // The single-continuation path below only builds the state continuation
        // at output 0, so the built tx's outputs would mismatch hashOutputs and
        // input 0's OP_VERIFY would reject. Rebuild an ORDERED contract-outputs
        // list from the interpreter's source-ordered output list. Purely
        // additive: absent raw outputs this is a no-op and existing behaviour
        // is byte-for-byte untouched.
        List<TransactionBuilder.ContractOutput> orderedContractOutputs = null;
        int continuationIndex = 0;
        boolean hasRawOutput = false;
        for (AnfInterpreter.OrderedOutput o : orderedOutputs) {
            if ("raw".equals(o.kind())) { hasRawOutput = true; break; }
        }
        if (isStateful && hasRawOutput) {
            long stateCount = orderedOutputs.stream()
                .filter(o -> "state".equals(o.kind())).count();
            // Fail closed. The OP_PUSH_TX machinery below threads exactly one
            // newLockingScript / newSats, so multiple continuations interleaved
            // with raw outputs — or a missing continuation script — are not
            // representable. Throw rather than silently drop outputs and strand
            // the funds.
            if (stateCount >= 2 || (stateCount == 1 && newLockingScript == null)) {
                throw new IllegalStateException(
                    "RunarContract.call('" + methodName + "'): cannot build a transaction "
                        + "that interleaves raw outputs with " + stateCount + " state "
                        + "continuations; the SDK currently supports raw outputs alongside "
                        + "a single state continuation only (finding G1)."
                );
            }
            orderedContractOutputs = new ArrayList<>(orderedOutputs.size());
            int idx = 0;
            for (AnfInterpreter.OrderedOutput o : orderedOutputs) {
                if ("raw".equals(o.kind())) {
                    orderedContractOutputs.add(
                        new TransactionBuilder.ContractOutput(o.satoshis(), o.script())
                    );
                } else { // state continuation — use the fresh continuation script
                    orderedContractOutputs.add(
                        new TransactionBuilder.ContractOutput(o.satoshis(), newLockingScript)
                    );
                    continuationIndex = idx;
                    // Sync the preimage's newAmount to the continuation output's
                    // sats — this.addOutput(0L, ...) makes it 0, not the input
                    // value the single-continuation path defaulted to.
                    newSats = o.satoshis();
                }
                idx++;
            }
        }

        // Funding from the signer's P2PKH UTXOs (largest-first selection).
        // Stateless OP_PUSH_TX contracts also need a fee source because
        // the contract input typically forwards all sats to a continuation
        // or back to a P2PKH output.
        String funderAddress = signer.address();
        List<UTXO> all = provider.listUtxos(funderAddress);
        List<UTXO> additional = new ArrayList<>();
        for (UTXO u : all) {
            if (!(u.txid().equals(currentUtxo.txid()) && u.outputIndex() == currentUtxo.outputIndex())) {
                additional.add(u);
            }
        }

        long feeRate = provider.getFeeRate();
        String changePkhHex = null;
        if (methodNeedsChange) {
            byte[] pkhBytes = Hash160.hash160(signer.pubKey());
            changePkhHex = ScriptUtils.bytesToHex(pkhBytes);
        }

        // Code-separator-aware sighash subscript for the contract input
        // (and also the scriptCode used inside the BIP-143 preimage that
        // OP_PUSH_TX hashes). For stateful contracts the compiler emits
        // an OP_CODESEPARATOR; everything before it is excluded from the
        // sighash subscript.
        int methodIndex = findPublicMethodIndex(methodName);
        int codeSepIdx = getCodeSepIndex(methodIndex);
        String fullScriptHex = currentUtxo.scriptHex();
        String sighashSubscript = codeSepIdx >= 0
            ? fullScriptHex.substring((codeSepIdx + 1) * 2)
            : fullScriptHex;

        // The BIP-143 preimage placeholder MUST be the length the real preimage
        // will be, because both layout passes below fix the change output — and
        // therefore the fee — from the size of the unlock they are handed, and
        // the real preimage is spliced in afterwards with no further layout. A
        // fixed 181-byte stand-in encodes a 24-byte scriptCode; a real contract's
        // scriptCode is its own (post-OP_CODESEPARATOR) locking script, so the
        // tx broadcast was hundreds of bytes larger than the one the fee was
        // computed for and under-paid the miner. The length is fully determined
        // by the scriptCode — every other BIP-143 field is fixed-width — so
        // sizing it here makes the layout byte-exact.
        String preimagePlaceholder = "00".repeat(bip143PreimageLen(sighashSubscript));

        // Extra contract inputs (merge / swap / any multi-input covenant).
        // Each carries its OWN args, its own auto-signed Sig slots and its own
        // BIP-143 preimage bound to its own outpoint; only the SDK-side layout
        // is shared. Empty in the single-input case, where everything below is
        // a no-op and the built tx is byte-for-byte unchanged.
        List<UTXO> extraContractUtxos = options == null || options.additionalContractInputs == null
            ? List.of() : options.additionalContractInputs;
        List<List<Object>> perInputArgs = options == null ? null : options.additionalContractInputArgs;
        if (perInputArgs != null && perInputArgs.size() > extraContractUtxos.size()) {
            throw new IllegalArgumentException(
                "RunarContract.call(" + methodName + "): additionalContractInputArgs has "
                    + perInputArgs.size() + " entr" + (perInputArgs.size() == 1 ? "y" : "ies")
                    + " but additionalContractInputs has " + extraContractUtxos.size()
                    + ". Each arg list overrides the args for the input at the same index; "
                    + "extra lists would be silently dropped.");
        }

        // Per-input resolved args and the Sig slots to sign for each.
        List<List<Object>> extraResolved = new ArrayList<>();
        List<List<Integer>> extraSigIndices = new ArrayList<>();
        List<RunarArtifact.ABIParam> userParamsForExtra = userParams(m, isStateful);
        for (int i = 0; i < extraContractUtxos.size(); i++) {
            List<Object> baseArgs = (perInputArgs != null && i < perInputArgs.size()
                && perInputArgs.get(i) != null)
                ? perInputArgs.get(i)
                : userArgsOf(resolved, userParamsForExtra.size());
            if (baseArgs.size() != userParamsForExtra.size()) {
                throw new IllegalArgumentException(
                    "RunarContract.call(" + methodName + "): additionalContractInputArgs[" + i
                        + "] has " + baseArgs.size() + " args, method expects "
                        + userParamsForExtra.size());
            }
            List<Object> r = new ArrayList<>(baseArgs);
            List<Integer> sigs = new ArrayList<>();
            for (int j = 0; j < userParamsForExtra.size(); j++) {
                RunarArtifact.ABIParam p = userParamsForExtra.get(j);
                if ("Sig".equals(p.type()) && r.get(j) == null) {
                    sigs.add(j);
                    r.set(j, "00".repeat(72));
                } else if ("PubKey".equals(p.type()) && r.get(j) == null) {
                    r.set(j, ScriptUtils.bytesToHex(signer.pubKey()));
                } else if (isAutoPrevoutsParam(p, r.get(j))) {
                    r.set(j, "00".repeat(36 * (1 + extraContractUtxos.size() + 1)));
                } else {
                    rejectUnresolvableNullArg(
                        "RunarContract.call(additionalContractInputArgs[" + i + "])", p, j, r.get(j));
                }
            }
            extraResolved.add(r);
            extraSigIndices.add(sigs);
        }

        // Sighash subscript for each extra input, from ITS OWN locking script.
        List<String> extraSubscripts = new ArrayList<>();
        for (UTXO u : extraContractUtxos) {
            extraSubscripts.add(codeSepIdx >= 0
                ? u.scriptHex().substring((codeSepIdx + 1) * 2)
                : u.scriptHex());
        }

        // `allPrevouts` is 36 bytes PER INPUT, and its real value is only known
        // after coin selection — but it is spliced in after the layout passes
        // have already fixed the change output. So its stand-in has to be the
        // right LENGTH going in, exactly like the BIP-143 preimage above. A
        // fixed guess of "contract + extras + one funding input" under-sizes
        // every call that needs more than one funding coin: with 5 funding
        // inputs the two unlocks are 288 bytes short and the tx under-pays.
        // Converge on the real count by laying out, reading back how many
        // funding inputs were actually selected, and re-sizing.
        List<Integer> prevoutsIdx = prevoutsIndices(userParamsForExtra);
        int assumedInputs = 1 + extraContractUtxos.size() + 1;
        if (!prevoutsIdx.isEmpty()) {
            boolean converged = false;
            for (int attempt = 0; attempt < 4 && !converged; attempt++) {
                setPrevoutsPlaceholder(resolved, extraResolved, prevoutsIdx, assumedInputs);
                String probeUnlock = buildPushTxUnlock(
                    m, methodName, resolved, "00".repeat(72),
                    methodNeedsChange ? changePkhHex : null,
                    0L, methodNeedsNewAmount, newSats, preimagePlaceholder, intentWitnessHex);
                List<TransactionBuilder.ContractInput> probeExtras = buildExtraInputPlaceholders(
                    m, methodName, extraContractUtxos, extraResolved, extraSubscripts,
                    methodNeedsChange ? changePkhHex : null, methodNeedsNewAmount, newSats,
                    intentWitnessHex);
                TransactionBuilder.CallTxResult probe = orderedContractOutputs != null
                    ? TransactionBuilder.buildCallTransactionFullOrdered(
                        currentUtxo, probeUnlock, orderedContractOutputs,
                        dataOutputs, additional, funderAddress, feeRate, locktime, probeExtras)
                    : TransactionBuilder.buildCallTransactionFull(
                        currentUtxo, probeUnlock, newLockingScript, newSats,
                        dataOutputs, additional, funderAddress, feeRate, locktime, probeExtras);
                int actualInputs = 1 + extraContractUtxos.size() + probe.fundingUtxos().size();
                if (actualInputs == assumedInputs) converged = true;
                else assumedInputs = actualInputs;
            }
            if (!converged) {
                // Fail closed rather than broadcast a transaction whose fee was
                // computed for a different size than the one it ships.
                throw new IllegalStateException(
                    "RunarContract.call(" + methodName + "): could not settle the input count "
                        + "for the auto-computed 'allPrevouts' argument (last estimate "
                        + assumedInputs + "). Pass an explicit allPrevouts value, or reduce "
                        + "the number of funding UTXOs in play.");
            }
        }

        // First pass: build a placeholder unlock so we can size the tx,
        // estimate the fee, lay out outputs, and compute the change
        // amount that will be embedded in the real unlock.
        String placeholderUnlock = buildPushTxUnlock(
            m, methodName, resolved, /*opPushTxSigHex*/ "00".repeat(72),
            methodNeedsChange ? changePkhHex : null,
            /*changeAmount*/ 0L, methodNeedsNewAmount, newSats,
            /*preimageHex*/ preimagePlaceholder,
            intentWitnessHex
        );

        // Correctly-sized placeholder unlocks for the extra inputs, so the fee
        // covers their bytes too.
        List<TransactionBuilder.ContractInput> extraInputs = buildExtraInputPlaceholders(
            m, methodName, extraContractUtxos, extraResolved, extraSubscripts,
            methodNeedsChange ? changePkhHex : null, methodNeedsNewAmount, newSats,
            intentWitnessHex);

        // Thread CallOptions.locktime so contracts asserting
        // extractLocktime(preimage) can succeed. 0 → legacy. The rebuild path
        // below must honor the same value or its preimage would mismatch the
        // final on-chain tx.
        TransactionBuilder.CallTxResult firstPass = orderedContractOutputs != null
            ? TransactionBuilder.buildCallTransactionFullOrdered(
                currentUtxo, placeholderUnlock, orderedContractOutputs,
                dataOutputs, additional, funderAddress, feeRate, locktime, extraInputs
            )
            : TransactionBuilder.buildCallTransactionFull(
                currentUtxo, placeholderUnlock, newLockingScript, newSats,
                dataOutputs, additional, funderAddress, feeRate, locktime, extraInputs
            );
        long changeAmount = firstPass.changeAmount();

        // Second pass: rebuild the unlock with the (now-known) change
        // amount, then re-lay out the tx. The unlock size may change a
        // few bytes between passes when the change amount's
        // script-number encoding crosses a length boundary, so we run
        // through the layout once more.
        String secondPassUnlock = buildPushTxUnlock(
            m, methodName, resolved, /*opPushTxSigHex*/ "00".repeat(72),
            methodNeedsChange ? changePkhHex : null,
            changeAmount, methodNeedsNewAmount, newSats,
            /*preimageHex*/ preimagePlaceholder,
            intentWitnessHex
        );
        TransactionBuilder.CallTxResult secondPass = orderedContractOutputs != null
            ? TransactionBuilder.buildCallTransactionFullOrdered(
                currentUtxo, secondPassUnlock, orderedContractOutputs,
                dataOutputs, additional, funderAddress, feeRate, locktime, extraInputs
            )
            : TransactionBuilder.buildCallTransactionFull(
                currentUtxo, secondPassUnlock, newLockingScript, newSats,
                dataOutputs, additional, funderAddress, feeRate, locktime, extraInputs
            );
        long finalChangeAmount = secondPass.changeAmount();
        RawTx tx = secondPass.tx();

        // Funding inputs actually placed on the tx (issue #133): the builder
        // coin-selects the smallest largest-first set that covers outputs + fee,
        // so sign THOSE — not the whole swept wallet. Iterating the full sweep
        // both over-signs and (when selected < swept) indexes past the tx's
        // inputs. Cap the funding-input count when maxFundingInputs is set:
        // selection is minimal, so exceeding the cap means outputs + fee cannot
        // be covered within the budget — fail loudly instead of broadcasting an
        // underfunded tx.
        List<UTXO> usedFunding = secondPass.fundingUtxos();
        if (maxFundingInputs != null && usedFunding.size() > maxFundingInputs) {
            throw new IllegalStateException(
                "RunarContract.call(" + methodName + "): funding requires "
                    + usedFunding.size() + " input(s) but maxFundingInputs="
                    + maxFundingInputs + ". Increase maxFundingInputs, use larger UTXOs, "
                    + "or consolidate.");
        }

        // Sequence (issue #131): an all-0xffffffff input set makes nLockTime a
        // consensus no-op. When a non-zero locktime is set, default every input
        // to 0xfffffffe (non-final) so the locktime is actually enforced.
        // Explicit options.sequence always wins. Set BEFORE the OP_PUSH_TX
        // preimage / BIP-143 sighashes are computed so they cover the final
        // sequences.
        tx.setAllSequences(resolveInputSequence(optLocktime, optSequence));

        // Compute the OP_PUSH_TX (k=1, d=1) signature + the preimage now
        // that the tx layout is settled. The on-chain script re-derives
        // the same sighash from the spliced preimage and verifies the
        // signature against G; if either differs by a single byte the
        // node rejects the spend.
        // Issue #123: build the covenant preimage + derived signature under the
        // method's declared @sighash mode (default 0x41 = ALL|FORKID). The mode
        // drives both which BIP-143 fields are zeroed and the appended flag byte.
        int methodSigHash = m.sigHashType() != null ? m.sigHashType() : OpPushTx.SIGHASH_ALL_FORKID;

        // The input set is now final, so the auto-computed `allPrevouts` value
        // exists. Fill it in every arg list — the primary input's and each
        // extra input's — BEFORE any preimage or signature is derived, since
        // they all commit to these bytes. Same length as the stand-in whenever
        // the funding estimate held; when it did not, the layout below still
        // reflects the real bytes because the unlocks are rebuilt from here.
        if (!prevoutsIdx.isEmpty()) {
            String prevouts = allPrevoutsHex(tx);
            for (int idx : prevoutsIdx) {
                resolved.set(idx, prevouts);
                for (List<Object> r : extraResolved) r.set(idx, prevouts);
            }
        }

        byte[] preimage = OpPushTx.preimage(
            tx, 0, ScriptUtils.hexToBytes(sighashSubscript),
            currentUtxo.satoshis(), methodSigHash
        );
        byte[] opPushTxSig = OpPushTx.computePushTxSig(
            tx, 0, sighashSubscript, currentUtxo.satoshis(), methodSigHash
        );

        // Sign Sig placeholders against the same code-separator-aware
        // sighash the contract input enforces (issue #123: under the method's mode).
        if (!sigIndices.isEmpty()) {
            byte[] userSighash = tx.sighashBIP143(
                0, sighashSubscript, currentUtxo.satoshis(), methodSigHash
            );
            for (int idx : sigIndices) {
                byte[] der = signer.sign(userSighash, null);
                String sigHex = ScriptUtils.bytesToHex(der)
                    + String.format("%02x", methodSigHash & 0xff);
                resolved.set(idx, sigHex);
            }
        }

        String finalUnlock = buildPushTxUnlock(
            m, methodName, resolved,
            ScriptUtils.bytesToHex(opPushTxSig),
            methodNeedsChange ? changePkhHex : null,
            finalChangeAmount, methodNeedsNewAmount, newSats,
            ScriptUtils.bytesToHex(preimage),
            intentWitnessHex
        );
        tx.setUnlockingScript(0, finalUnlock);

        // Each extra contract input gets its own unlock: its own BIP-143
        // preimage (bound to ITS outpoint via inputIndex and to its own
        // scriptCode), its own OP_PUSH_TX signature, and its own Sig args
        // signed against its own sighash. Sharing input 0's unlock would make
        // every covenant after the first verify the wrong outpoint.
        for (int i = 0; i < extraContractUtxos.size(); i++) {
            int inputIdx = 1 + i;
            UTXO u = extraContractUtxos.get(i);
            String subscript = extraSubscripts.get(i);
            byte[] extraPreimage = OpPushTx.preimage(
                tx, inputIdx, ScriptUtils.hexToBytes(subscript), u.satoshis(), methodSigHash);
            byte[] extraPushTxSig = OpPushTx.computePushTxSig(
                tx, inputIdx, subscript, u.satoshis(), methodSigHash);
            List<Object> r = extraResolved.get(i);
            List<Integer> sigs = extraSigIndices.get(i);
            if (!sigs.isEmpty()) {
                byte[] extraSighash = tx.sighashBIP143(
                    inputIdx, subscript, u.satoshis(), methodSigHash);
                for (int idx : sigs) {
                    byte[] der = signer.sign(extraSighash, null);
                    r.set(idx, ScriptUtils.bytesToHex(der)
                        + String.format("%02x", methodSigHash & 0xff));
                }
            }
            tx.setUnlockingScript(inputIdx, buildPushTxUnlock(
                m, methodName, r, ScriptUtils.bytesToHex(extraPushTxSig),
                methodNeedsChange ? changePkhHex : null,
                finalChangeAmount, methodNeedsNewAmount, newSats,
                ScriptUtils.bytesToHex(extraPreimage),
                intentWitnessHex));
        }

        // Sign each P2PKH funding input (after the contract inputs). Signed by
        // fundingSigner (issue #134); the method's own Sig args stay with the
        // connected signer. Only the coin-selected funding inputs are on the tx
        // (issue #133), so iterate those.
        for (int i = 0; i < usedFunding.size(); i++) {
            int inputIdx = 1 + extraContractUtxos.size() + i;
            UTXO u = usedFunding.get(i);
            byte[] fundSighash = tx.sighashBIP143(
                inputIdx, u.scriptHex(), u.satoshis(), RawTx.SIGHASH_ALL_FORKID
            );
            byte[] der = fundingSigner.sign(fundSighash, null);
            String fundSigHex = ScriptUtils.bytesToHex(der)
                + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
            String fundUnlock = ScriptUtils.encodePushData(fundSigHex)
                + ScriptUtils.encodePushData(ScriptUtils.bytesToHex(fundingSigner.pubKey()));
            tx.setUnlockingScript(inputIdx, fundUnlock);
        }

        String txHex = tx.toHex();
        String txid = provider.broadcastRaw(txHex);

        UTXO nextUtxo = null;
        if (isStateful && newLockingScript != null) {
            // The state continuation is normally output 0, but a method that
            // also calls this.addRawOutput(...) (finding G1) can push raw
            // outputs ahead of it — track it at its real source-order index and
            // its real sats (which may legitimately be 0). The no-raw path
            // keeps index 0 / newSats unchanged.
            int contIdx = orderedContractOutputs != null ? continuationIndex : 0;
            nextUtxo = new UTXO(txid, contIdx, newSats, newLockingScript);
            this.currentUtxo = nextUtxo;
        } else {
            this.currentUtxo = null;
        }
        return new CallOutcome(txid, txHex, nextUtxo);
    }

    /**
     * Terminal call path. The contract is fully spent: the tx has the
     * contract UTXO as its first signed input (plus any caller-supplied
     * funding UTXOs as P2PKH inputs), the outputs are exactly the
     * caller-supplied {@link CallOptions#terminalOutputs}, and there is
     * no continuation and no change. Fee comes implicitly from the
     * difference between input value and output value.
     *
     * <p>For stateful contracts this still runs the OP_PUSH_TX two-pass
     * convergence — the on-chain script enforces the BIP-143 preimage
     * regardless of whether a continuation is produced. For stateless
     * contracts (or stateful methods without {@code _changePKH}) this
     * just signs Sig placeholders and broadcasts.
     */
    private CallOutcome callTerminal(
        RunarArtifact.ABIMethod m,
        String methodName,
        List<Object> resolved,
        List<Integer> sigIndices,
        boolean methodNeedsChange,
        boolean methodNeedsNewAmount,
        boolean isStateful,
        boolean parentStateful,
        List<CallOptions.TerminalOutput> terminalOutputs,
        List<UTXO> fundingUtxos,
        Provider provider,
        Signer signer,
        int locktime,
        CallOptions options
    ) {
        // Funding (and terminal fee) inputs are signed by fundingSigner when set
        // (issue #134); the method's own Sig args stay with the connected signer.
        Signer fundingSigner = (options != null && options.fundingSigner != null)
            ? options.fundingSigner : signer;
        Integer optSequence = options != null ? options.sequence : null;
        Integer optLocktime = options != null ? options.locktime : null;
        long termSequence = resolveInputSequence(optLocktime, optSequence);

        // Fee input (issue #118): a single plain P2PKH UTXO added to the
        // terminal tx purely to pay the miner fee. A true terminal method pays
        // out the full contract balance, so fee would be 0 and ARC rejects; the
        // covenant asserts its exact output set, so no change output can absorb a
        // fee. The fee input is added BEFORE the OP_PUSH_TX preimage (so
        // hashPrevouts covers it) and consumed entirely as fee — no change
        // output. Reconciled with the existing terminal funding mechanism by
        // prepending it to the funding list so it sits at input index 1 (right
        // after the primary contract input) and is signed like any funding
        // input (with fundingSigner).
        UTXO feeUtxo = options != null ? options.feeUtxo : null;
        List<UTXO> effectiveFunding = new ArrayList<>();
        if (feeUtxo != null) effectiveFunding.add(feeUtxo);
        effectiveFunding.addAll(fundingUtxos);

        // Pre-resolve intent-intrinsic witness hex. Throws
        // WitnessValueMissingError BEFORE any signing / broadcast.
        String intentWitnessHex = buildIntentWitnessHex(m);

        // parentStateful pulls a zero-mutable-field StatefulSmartContract into
        // the OP_PUSH_TX / codesep-aware path so the terminal user checkSig
        // signs the trimmed subscript (issue #44).
        boolean needsOpPushTx = parentStateful || isStateful || hasParam(m, "txPreimage");
        long contractSats = currentUtxo.satoshis();

        // Resolve user-facing outputs into hex-encoded scripts. Throws if
        // any entry has neither address nor scriptHex (validated in
        // TerminalOutput's compact constructor).
        record OutEntry(long sats, String scriptHex) {}
        List<OutEntry> outs = new ArrayList<>();
        long termOutSats = 0;
        for (CallOptions.TerminalOutput t : terminalOutputs) {
            long s = t.satoshis().longValueExact();
            outs.add(new OutEntry(s, t.resolveScriptHex()));
            termOutSats += s;
        }

        // Sanity: contract balance + funding (incl. any feeUtxo) must cover
        // output sum. The surplus over outputs becomes the miner fee.
        long fundingSats = 0;
        for (UTXO fu : effectiveFunding) fundingSats += fu.satoshis();
        if (contractSats + fundingSats < termOutSats) {
            throw new IllegalStateException(
                "RunarContract.call: terminal outputs (" + termOutSats
                    + " sats) exceed contract balance (" + contractSats
                    + ") + funding (" + fundingSats + ")"
            );
        }

        // Build a tx layout: contract input + funding inputs (feeUtxo first, at
        // index 1) + terminal outputs. The unlocking script for the contract
        // input is sized up front (placeholder for stateful, real for
        // stateless+no-Sig) so OP_PUSH_TX preimage / Sig sighashes can be
        // computed against the final tx bytes. Input sequences are set for
        // issue #131 (non-final when a non-zero locktime is enforced).
        java.util.function.Supplier<RawTx> buildTx = () -> {
            RawTx t = new RawTx();
            // Terminal calls (auction close/claim/withdraw) typically assert
            // extractLocktime(preimage) >= deadline. Default 0 preserves legacy
            // behavior for contracts that don't check locktime.
            t.locktime = locktime;
            t.addInput(currentUtxo.txid(), currentUtxo.outputIndex(), "");
            for (UTXO fu : effectiveFunding) {
                t.addInput(fu.txid(), fu.outputIndex(), "");
            }
            for (OutEntry o : outs) {
                t.addOutput(o.sats(), o.scriptHex());
            }
            t.setAllSequences(termSequence);
            return t;
        };

        String contractUnlock;
        String opPushTxSigHex = null;
        String preimageHex = null;

        // Issue #123: the terminal method's declared @sighash mode (default 0x41).
        int methodSigHash = m.sigHashType() != null ? m.sigHashType() : OpPushTx.SIGHASH_ALL_FORKID;

        if (isStateful || needsOpPushTx) {
            // Code-separator-aware sighash subscript for the contract input.
            int methodIndex = findPublicMethodIndex(methodName);
            int codeSepIdx = getCodeSepIndex(methodIndex);
            String fullScriptHex = currentUtxo.scriptHex();
            String sighashSubscript = codeSepIdx >= 0
                ? fullScriptHex.substring((codeSepIdx + 1) * 2)
                : fullScriptHex;

            // Pass 1: placeholder unlock so we can compute the preimage
            // against a tx with the correct output layout.
            String placeholderUnlock = buildPushTxUnlock(
                m, methodName, resolved, "00".repeat(72),
                methodNeedsChange ? "00".repeat(20) : null,
                /*changeAmount*/ 0L, methodNeedsNewAmount, /*newSats*/ 0L,
                "00".repeat(181),
                intentWitnessHex
            );
            RawTx tx = buildTx.get();
            tx.setUnlockingScript(0, placeholderUnlock);
            byte[] preimage = OpPushTx.preimage(
                tx, 0, ScriptUtils.hexToBytes(sighashSubscript),
                contractSats, methodSigHash
            );
            byte[] opPushTxSig = OpPushTx.computePushTxSig(
                tx, 0, sighashSubscript, contractSats, methodSigHash
            );
            opPushTxSigHex = ScriptUtils.bytesToHex(opPushTxSig);
            preimageHex = ScriptUtils.bytesToHex(preimage);

            // Sign Sig placeholders against the same code-separator-aware
            // sighash the contract input enforces (issue #123: under the method's mode).
            if (!sigIndices.isEmpty()) {
                byte[] userSighash = tx.sighashBIP143(
                    0, sighashSubscript, contractSats, methodSigHash
                );
                for (int idx : sigIndices) {
                    byte[] der = signer.sign(userSighash, null);
                    String sigHex = ScriptUtils.bytesToHex(der)
                        + String.format("%02x", methodSigHash & 0xff);
                    resolved.set(idx, sigHex);
                }
            }

            contractUnlock = buildPushTxUnlock(
                m, methodName, resolved, opPushTxSigHex,
                /*changePkhHex (terminal: no change)*/ null,
                /*changeAmount*/ 0L, methodNeedsNewAmount, /*newSats*/ 0L,
                preimageHex,
                intentWitnessHex
            );
        } else {
            // Pure stateless terminal — sign each Sig against the
            // contract-input sighash on the final tx layout.
            String placeholderUnlock = buildUnlockingScript(m, resolved) + intentWitnessHex;
            RawTx tx = buildTx.get();
            tx.setUnlockingScript(0, placeholderUnlock);
            if (!sigIndices.isEmpty()) {
                byte[] sighash = tx.sighashBIP143(
                    0, currentUtxo.scriptHex(), contractSats, methodSigHash
                );
                for (int idx : sigIndices) {
                    byte[] der = signer.sign(sighash, null);
                    String sigHex = ScriptUtils.bytesToHex(der)
                        + String.format("%02x", methodSigHash & 0xff);
                    resolved.set(idx, sigHex);
                }
            }
            contractUnlock = buildUnlockingScript(m, resolved) + intentWitnessHex;
        }

        RawTx finalTx = buildTx.get();
        finalTx.setUnlockingScript(0, contractUnlock);

        // Sign each funding input (feeUtxo first, at index 1 — issue #118),
        // signed by fundingSigner (issue #134). Each P2PKH BIP-143 sighash
        // covers only hashPrevouts / hashOutputs / its own outpoint — NOT input
        // 0's scriptSig — so it stays valid regardless of the covenant unlock.
        for (int i = 0; i < effectiveFunding.size(); i++) {
            int inputIdx = 1 + i;
            UTXO fu = effectiveFunding.get(i);
            byte[] fundSighash = finalTx.sighashBIP143(
                inputIdx, fu.scriptHex(), fu.satoshis(), RawTx.SIGHASH_ALL_FORKID
            );
            byte[] der = fundingSigner.sign(fundSighash, null);
            String fundSigHex = ScriptUtils.bytesToHex(der)
                + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
            String fundUnlock = ScriptUtils.encodePushData(fundSigHex)
                + ScriptUtils.encodePushData(ScriptUtils.bytesToHex(fundingSigner.pubKey()));
            finalTx.setUnlockingScript(inputIdx, fundUnlock);
        }

        String txHex = finalTx.toHex();
        String txid = provider.broadcastRaw(txHex);
        this.currentUtxo = null;
        return new CallOutcome(txid, txHex, null);
    }

    /**
     * Builds a full OP_PUSH_TX-style unlocking script:
     *   [_codePart] user_args [_changePKH _changeAmount]
     *   [_newAmount] preimage [methodSelector]
     *
     * <p>BUG-100 fix: no OP_PUSH_TX signature is pushed — it is derived
     * on-chain from the preimage (see codegen emitCheckPreimageBinding).
     *
     * <p>{@code changePkhHex} may be {@code null} when the method does
     * not need a change PKH; same for {@code methodNeedsNewAmount}.
     */
    private String buildPushTxUnlock(
        RunarArtifact.ABIMethod m,
        String methodName,
        List<Object> userArgs,
        String opPushTxSigHex,
        String changePkhHex,
        long changeAmount,
        boolean methodNeedsNewAmount,
        long newSatoshis,
        String preimageHex,
        String intentWitnessHex
    ) {
        StringBuilder sb = new StringBuilder();

        // _codePart push. New artifacts carry the authoritative usesCodePart
        // flag — true for continuation builders AND terminal var-length-state
        // readers (issue #100). Older artifacts omit it; fall back to the
        // legacy rule (codePart iff change, i.e. changePkhHex present).
        boolean usesCodePart = m.usesCodePart() != null ? m.usesCodePart() : (changePkhHex != null);
        if (usesCodePart) {
            sb.append(ScriptUtils.encodePushData(getCodePartHex()));
        }

        // BUG-100 fix: the OP_PUSH_TX signature is now derived on-chain from the
        // preimage (see codegen emitCheckPreimageBinding), so NO signature is
        // pushed here — the unlocking script carries only _codePart (if needed)
        // and the preimage. The opPushTxSigHex parameter is retained for
        // call-site compatibility but ignored.

        // User args (already resolved).
        for (int i = 0; i < userArgs.size(); i++) {
            Object arg = userArgs.get(i);
            String type = i < m.params().size() ? m.params().get(i).type() : "ByteString";
            sb.append(ContractScript.encodeConstructorArg(arg, type));
        }

        // _changePKH + _changeAmount
        if (changePkhHex != null) {
            sb.append(ScriptUtils.encodePushData(changePkhHex));
            sb.append(ContractScript.encodeConstructorArg(java.math.BigInteger.valueOf(changeAmount), "bigint"));
        }

        // _newAmount
        if (methodNeedsNewAmount) {
            sb.append(ContractScript.encodeConstructorArg(java.math.BigInteger.valueOf(newSatoshis), "bigint"));
        }

        // Preimage push.
        sb.append(ScriptUtils.encodePushData(preimageHex));

        // Intent-intrinsic witness pushes (`_prevOutScript_*` then
        // `_serialisedOutputs`, ABI order). Empty when the method has no
        // auto-injected intent params.
        if (intentWitnessHex != null && !intentWitnessHex.isEmpty()) {
            sb.append(intentWitnessHex);
        }

        // Method selector (only when the contract has multiple public methods).
        int publicMethodCount = countPublicMethods();
        if (publicMethodCount > 1) {
            int idx = findPublicMethodIndex(methodName);
            sb.append(ContractScript.encodeConstructorArg(
                java.math.BigInteger.valueOf(idx), "bigint"
            ));
        }

        return sb.toString();
    }

    /** Returns the code part of the locking script (everything before the last OP_RETURN). */
    private String getCodePartHex() {
        return ContractScript.extractCodePart(currentUtxo.scriptHex());
    }

    private int countPublicMethods() {
        int n = 0;
        for (RunarArtifact.ABIMethod m : artifact.abi().methods()) {
            if (m.isPublic()) n++;
        }
        return n;
    }

    /**
     * Byte length of the BIP-143 preimage for a given scriptCode. Every field
     * other than the scriptCode is fixed-width:
     *
     * <pre>
     *   4 nVersion + 32 hashPrevouts + 32 hashSequence + 36 outpoint
     * + varint(scriptCodeLen) + scriptCodeLen
     * + 8 amount + 4 nSequence + 32 hashOutputs + 4 nLocktime + 4 sighashType
     * </pre>
     *
     * so the total is exactly {@code 156 + varint + scriptCodeLen}. Used to size
     * the preimage stand-in in the call-layout passes; a stand-in of the wrong
     * length silently mis-sizes the fee (see the comment at its use site).
     *
     * @param scriptCodeHex the sighash subscript, hex-encoded
     */
    static int bip143PreimageLen(String scriptCodeHex) {
        int scriptCodeLen = scriptCodeHex.length() / 2;
        int varintLen = scriptCodeLen < 0xfd ? 1
            : scriptCodeLen <= 0xffff ? 3
            : scriptCodeLen <= 0xffffffffL ? 5 : 9;
        return 156 + varintLen + scriptCodeLen;
    }

    private int findPublicMethodIndex(String methodName) {
        int i = 0;
        for (RunarArtifact.ABIMethod m : artifact.abi().methods()) {
            if (!m.isPublic()) continue;
            if (m.name().equals(methodName)) return i;
            i++;
        }
        return -1;
    }

    /**
     * Returns the byte offset of an {@code OP_CODESEPARATOR} for the given
     * method index, or -1 if none is present.
     *
     * <p>When the contract has a live on-chain script ({@code currentUtxo} set),
     * walk the actual script and return the true on-chain byte position. This is
     * required because a contract reconnected from chain (or deployed from real
     * constructor args) carries args already baked into the locking script — so
     * {@link #adjustCodeSepOffset} computes a shift of zero and returns the
     * wrong offset whenever the {@code OP_CODESEPARATOR} sits after constructor
     * slots that expand at deploy time (issue #42: NULLFAIL at OP_CHECKSIG for
     * terminal methods).
     *
     * <p>Falls back to the legacy template-adjusted offset for synthetic /
     * unit-test paths that have no live script available.
     */
    // Package-private (not private) so the #132 regression test can assert the
    // byte-walk behaviour directly. See RunarContractSdkFixesTest.
    int getCodeSepIndex(int methodIndex) {
        if (currentUtxo != null && currentUtxo.scriptHex() != null) {
            java.util.List<Integer> realOffsets =
                findCodesepOffsets(codeScriptForCodesepScan());
            if (artifact.codeSeparatorIndices() != null
                && methodIndex >= 0
                && methodIndex < artifact.codeSeparatorIndices().size()
                && methodIndex < realOffsets.size()) {
                return realOffsets.get(methodIndex);
            }
            if (artifact.codeSeparatorIndex() != null && !realOffsets.isEmpty()) {
                return realOffsets.get(0);
            }
        }

        if (artifact.codeSeparatorIndices() != null
            && methodIndex >= 0
            && methodIndex < artifact.codeSeparatorIndices().size()) {
            return adjustCodeSepOffset(artifact.codeSeparatorIndices().get(methodIndex));
        }
        if (artifact.codeSeparatorIndex() != null) {
            return adjustCodeSepOffset(artifact.codeSeparatorIndex());
        }
        return -1;
    }

    /**
     * The portion of the live locking script that {@link #getCodeSepIndex} is
     * allowed to byte-walk: the CODE part only.
     *
     * <p>Everything after the state {@code OP_RETURN} separator is raw state
     * data, not script — and several state field types are serialised with no
     * push prefix at all ({@link StateSerializer}: {@code int}/{@code bigint}
     * become 8 raw little-endian bytes, {@code PubKey}/{@code Sha256}/
     * {@code Point} the raw value). Walking those bytes as opcodes decodes
     * payload as script: a state byte equal to {@code 0xab} is recorded as a
     * phantom {@code OP_CODESEPARATOR}, and a byte sequence that reads as
     * {@code OP_PUSHDATA4} drives the cursor off the end of the script.
     *
     * <p>Mirrors the TS {@code _codeScript} (contract.ts {@code fromUtxo}) and
     * Go {@code codeScript} (sdk_contract.go {@code FromUtxo}) bound, including
     * the stateless carve-out: a contract with no state fields has no state
     * region, so its whole script is code.
     */
    private String codeScriptForCodesepScan() {
        String scriptHex = currentUtxo.scriptHex();
        if (!artifact.isStateful()) return scriptHex;
        return ContractScript.extractCodePart(scriptHex);
    }

    /**
     * Walks a hex-encoded script and returns the byte offsets of every
     * {@code OP_CODESEPARATOR} (0xab) that sits at a real opcode boundary
     * (i.e. not inside push-data). Correctly skips all BSV push opcodes
     * (0x01..0x4b, OP_PUSHDATA1/2/4).
     *
     * <p>Used by {@link #getCodeSepIndex} to recover the true on-chain byte
     * offsets when the in-memory constructor args don't reflect what was
     * actually baked into the locking script.
     */
    /**
     * Resolve the nSequence for a call tx's inputs (issue #131).
     *
     * <p>An all-{@code 0xffffffff} input set makes nLockTime a consensus no-op,
     * so a locktime-gated method would be script-enforced (via extractLocktime)
     * yet NOT consensus-enforced. When a non-zero locktime is set we therefore
     * default every input to {@code 0xfffffffe} (non-final, enforceable).
     * Explicit {@code sequence} always wins; with no/zero locktime we keep the
     * legacy {@code 0xffffffff}. Shared by the non-terminal and terminal build
     * sites so both stay byte-consistent.
     */
    static long resolveInputSequence(Integer locktime, Integer sequence) {
        if (sequence != null) return sequence & 0xffffffffL;
        if (locktime != null && locktime != 0) return 0xfffffffeL;
        return 0xffffffffL;
    }

    static java.util.List<Integer> findCodesepOffsets(String scriptHex) {
        java.util.List<Integer> out = new java.util.ArrayList<>();
        int off = 0;
        int n = scriptHex.length();
        while (off + 2 <= n) {
            int op = byteAt(scriptHex, off);
            int bytePos = off / 2;
            if (op == 0xab) {
                out.add(bytePos);
                off += 2;
            } else if (op >= 0x01 && op <= 0x4b) {
                off += 2 + op * 2;
            } else if (op == 0x4c) {
                if (off + 4 > n) break;
                int pushLen = byteAt(scriptHex, off + 2);
                off += 4 + pushLen * 2;
            } else if (op == 0x4d) {
                if (off + 6 > n) break;
                int lo = byteAt(scriptHex, off + 2);
                int hi = byteAt(scriptHex, off + 4);
                int pushLen = lo | (hi << 8);
                off += 6 + pushLen * 2;
            } else if (op == 0x4e) {
                if (off + 10 > n) break;
                int b0 = byteAt(scriptHex, off + 2);
                int b1 = byteAt(scriptHex, off + 4);
                int b2 = byteAt(scriptHex, off + 6);
                int b3 = byteAt(scriptHex, off + 8);
                // Widen to long: Java's int is signed, so b3 >= 0x80 makes the
                // OR result negative and walks the cursor backwards, forever or
                // past the start of the string (contract.ts uses `>>> 0` here).
                long pushLen = ((long) (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))) & 0xffffffffL;
                // A declared push length past the script end means a malformed
                // script; stop scanning rather than skipping into nothing.
                if (pushLen > (n - off - 10) / 2) break;
                off += 10 + (int) (pushLen * 2);
            } else {
                off += 2;
            }
        }
        return out;
    }

    private static int byteAt(String hex, int pos) {
        if (pos + 2 > hex.length()) return 0;
        try {
            return Integer.parseInt(hex.substring(pos, pos + 2), 16);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Adjusts a template code-separator offset to its post-substitution
     * byte position. Constructor-arg slots and earlier code-sep-index
     * slots replace 1-byte OP_0 placeholders with multi-byte pushes,
     * shifting subsequent offsets. Mirrors Go {@code adjustCodeSepOffset}.
     */
    private int adjustCodeSepOffset(int baseOffset) {
        int shift = 0;
        for (RunarArtifact.ConstructorSlot slot : artifact.constructorSlots()) {
            if (slot.byteOffset() < baseOffset && slot.paramIndex() < constructorArgs.size()) {
                String paramType = slot.paramIndex() < artifact.abi().constructor().params().size()
                    ? artifact.abi().constructor().params().get(slot.paramIndex()).type()
                    : "bigint";
                String enc = ContractScript.encodeConstructorArg(
                    constructorArgs.get(slot.paramIndex()), paramType
                );
                shift += enc.length() / 2 - 1;
            }
        }
        for (ContractScript.ResolvedCodeSep rs :
            ContractScript.resolvedCodeSepSlots(artifact, constructorArgs)) {
            if (rs.templateByteOffset() < baseOffset) {
                String enc = ContractScript.pushScriptNumber(
                    java.math.BigInteger.valueOf(rs.adjustedValue())
                );
                shift += enc.length() / 2 - 1;
            }
        }
        return baseOffset + shift;
    }

    /** Returns user-facing params (skips compiler-injected implicit params
     * for stateful methods and intent-intrinsic auto-injected witness params
     * for any method). Witness values come from
     * {@link #setPrevOutScript} / {@link #setSerialisedOutputs}, not from
     * the user args list. */
    private static List<RunarArtifact.ABIParam> userParams(RunarArtifact.ABIMethod m, boolean isStateful) {
        List<RunarArtifact.ABIParam> out = new ArrayList<>();
        for (RunarArtifact.ABIParam p : m.params()) {
            String n = p.name();
            String t = p.type();
            if (isAutoInjectedWitnessParam(n)) continue;
            if (isStateful) {
                if ("SigHashPreimage".equals(t)) continue;
                if ("_changePKH".equals(n) || "_changeAmount".equals(n) || "_newAmount".equals(n)) continue;
            }
            out.add(p);
        }
        return out;
    }

    /** True if {@code paramName} is an auto-injected intent-intrinsic
     * witness param ({@code _prevOutScript_<i>} or {@code _serialisedOutputs}). */
    private static boolean isAutoInjectedWitnessParam(String paramName) {
        return paramName.startsWith("_prevOutScript_") || "_serialisedOutputs".equals(paramName);
    }

    /**
     * The one {@code ByteString} parameter name the SDK auto-computes: the
     * concatenated outpoints of every input, which a multi-input covenant
     * hashes to bind the input set. Matches Go's {@code isAutoPrevoutsParam}
     * and the TS {@code AUTO_PREVOUTS_PARAM_NAME} convention.
     */
    static final String AUTO_PREVOUTS_PARAM_NAME = "allPrevouts";

    private static boolean isAutoPrevoutsParam(RunarArtifact.ABIParam param, Object value) {
        return value == null
            && "ByteString".equals(param.type())
            && AUTO_PREVOUTS_PARAM_NAME.equals(param.name());
    }

    /**
     * The first {@code n} entries of an already-resolved arg list — the user
     * params, before the compiler-injected {@code _changePKH} /
     * {@code _changeAmount} / {@code _newAmount} / {@code txPreimage} slots the
     * unlock builder appends itself. An extra contract input with no explicit
     * override reuses these.
     */
    private static List<Object> userArgsOf(List<Object> resolved, int n) {
        return new ArrayList<>(resolved.subList(0, Math.min(n, resolved.size())));
    }

    private static int extraContractInputCount(CallOptions options) {
        return options == null || options.additionalContractInputs == null
            ? 0 : options.additionalContractInputs.size();
    }

    /** Indices (into the user-arg list) of every auto-computed prevouts slot. */
    private static List<Integer> prevoutsIndices(List<RunarArtifact.ABIParam> userParams) {
        List<Integer> idx = new ArrayList<>();
        for (int i = 0; i < userParams.size(); i++) {
            if (AUTO_PREVOUTS_PARAM_NAME.equals(userParams.get(i).name())
                && "ByteString".equals(userParams.get(i).type())) {
                idx.add(i);
            }
        }
        return idx;
    }

    /**
     * Concatenated outpoints of every input, in input order:
     * {@code txid (little-endian) || vout (LE32)} per input. This is the
     * preimage of BIP-143's {@code hashPrevouts}, which is exactly what a
     * multi-input covenant re-hashes to prove it saw the whole input set.
     */
    /**
     * Re-size every auto-computed {@code allPrevouts} stand-in to
     * {@code inputCount} inputs' worth of outpoints (36 bytes each), across the
     * primary arg list and every extra input's. Length only — the real bytes go
     * in once the layout is settled.
     */
    private static void setPrevoutsPlaceholder(
        List<Object> resolved, List<List<Object>> extraResolved,
        List<Integer> prevoutsIdx, int inputCount
    ) {
        String stub = "00".repeat(36 * inputCount);
        for (int idx : prevoutsIdx) {
            resolved.set(idx, stub);
            for (List<Object> r : extraResolved) r.set(idx, stub);
        }
    }

    /**
     * Placeholder unlocks for the extra contract inputs, each sized against ITS
     * OWN scriptCode so the fee covers the bytes the tx will actually carry.
     */
    private List<TransactionBuilder.ContractInput> buildExtraInputPlaceholders(
        RunarArtifact.ABIMethod m, String methodName, List<UTXO> extraContractUtxos,
        List<List<Object>> extraResolved, List<String> extraSubscripts,
        String changePkhHex, boolean methodNeedsNewAmount, long newSats,
        String intentWitnessHex
    ) {
        List<TransactionBuilder.ContractInput> out = new ArrayList<>();
        for (int i = 0; i < extraContractUtxos.size(); i++) {
            out.add(new TransactionBuilder.ContractInput(
                extraContractUtxos.get(i),
                buildPushTxUnlock(
                    m, methodName, extraResolved.get(i), "00".repeat(72),
                    changePkhHex, 0L, methodNeedsNewAmount, newSats,
                    "00".repeat(bip143PreimageLen(extraSubscripts.get(i))),
                    intentWitnessHex)));
        }
        return out;
    }

    private static String allPrevoutsHex(RawTx tx) {
        StringBuilder sb = new StringBuilder();
        for (RawTx.Input in : tx.inputs) {
            sb.append(ScriptUtils.reverseHex(in.prevTxid));
            sb.append(ScriptUtils.toLittleEndian32(in.prevVout));
        }
        return sb.toString();
    }

    /**
     * Rejects a {@code null} call arg the SDK has no rule for resolving.
     *
     * <p>The Java tier auto-resolves exactly two slots: {@code Sig} (signed once
     * the tx layout settles) and {@code PubKey} (taken from the signer). A
     * {@code null} for a {@code ByteString} param is a caller mistake, and
     * letting it through means {@link ContractScript#encodeConstructorArg}
     * reaches its last resort — {@code encodePushData(String.valueOf(null))},
     * i.e. the literal string {@code "02null"} spliced into the unlocking-script
     * hex — or the call dies later with an opaque NullPointerException. Neither
     * names the parameter the caller got wrong.
     *
     * <p>Auto-injected intent-witness params ({@code _prevOutScript_<i>},
     * {@code _serialisedOutputs}) are exempt: their values come from
     * {@link #setPrevOutScript} / {@link #setSerialisedOutputs}, not the args
     * list, and {@link #buildIntentWitnessHex} already fails loudly when one is
     * unset.
     */
    private static void rejectUnresolvableNullArg(
        String where, RunarArtifact.ABIParam param, int index, Object value
    ) {
        if (value != null) return;
        if (!"ByteString".equals(param.type())) return;
        if (isAutoInjectedWitnessParam(param.name())) return;
        throw new IllegalArgumentException(
            where + ": null arg for " + param.type() + " param '" + param.name()
                + "' (index " + index + "): null is only auto-resolved for Sig "
                + "(auto-signed) and PubKey (taken from the signer). Pass an explicit "
                + "value (hex string, or \"\" for an empty ByteString)"
        );
    }

    private static boolean hasParam(RunarArtifact.ABIMethod m, String name) {
        for (RunarArtifact.ABIParam p : m.params()) {
            if (name.equals(p.name())) return true;
        }
        return false;
    }

    private static Map<String, Object> buildNamedArgs(
        List<RunarArtifact.ABIParam> userParams, List<Object> args
    ) {
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        for (int i = 0; i < userParams.size() && i < args.size(); i++) {
            out.put(userParams.get(i).name(), args.get(i));
        }
        return out;
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
        // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        ScriptSizeExceededError.assertScriptHexUnderLimit(
            currentUtxo.scriptHex(), InputLimits.MAX_SCRIPT_BYTES,
            artifact.contractName() + ".prepareCall(" + methodName + ")"
        );
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

        // Pre-resolve intent-intrinsic witness hex (throws
        // WitnessValueMissingError if any auto-injected param wasn't set).
        String intentWitnessHex = buildIntentWitnessHex(m);

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
            rejectUnresolvableNullArg(
                "RunarContract.prepareCall", m.params().get(i), i, resolved.get(i));
        }

        String unlockHex = buildUnlockingScript(m, resolved) + intentWitnessHex;
        Map<String, Object> continuation = artifact.isStateful() ? new java.util.LinkedHashMap<>(state) : null;
        long newSats = artifact.isStateful() ? currentUtxo.satoshis() : 0;

        TransactionBuilder.CallResult result = TransactionBuilder.buildCallTransaction(
            artifact, currentUtxo, unlockHex, continuation, newSats, provider, signer, null
        );
        // DoS-bound: also reject pathological continuation scripts BEFORE broadcast.
        if (result.newLockingScriptHex() != null) {
            ScriptSizeExceededError.assertScriptHexUnderLimit(
                result.newLockingScriptHex(), InputLimits.MAX_SCRIPT_BYTES,
                artifact.contractName() + ".prepareCall(" + methodName + ").continuation"
            );
        }
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
            // Issue #123: digest under the method's declared @sighash mode (default 0x41).
            int methodSigHash = m.sigHashType() != null ? m.sigHashType() : RawTx.SIGHASH_ALL_FORKID;
            sighash = computeContractSighash(txHex, 0, methodSigHash);
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
            newSats,
            intentWitnessHex
        );
    }

    public PreparedCall prepareCall(
        String methodName,
        List<Object> args,
        Provider provider,
        Signer signer
    ) {
        return prepareCall(methodName, args, (Map<String, Object>) null, provider, signer);
    }

    public PreparedCall prepareCall(
        String methodName,
        List<Object> args,
        Provider provider
    ) {
        return prepareCall(methodName, args, (Map<String, Object>) null, provider, null);
    }

    /**
     * Rich-options overload for {@link #prepareCall} that supports
     * terminal output spending. When {@code options.terminalOutputs} is
     * non-null, builds a no-continuation tx with exactly those outputs
     * (mirroring {@link #callWithOptions}) and returns a
     * {@link PreparedCall} with {@code newLockingScriptHex = null} and
     * {@code isStateful = false}-but-terminal-flagged via an empty
     * continuation. Distinct method name from
     * {@link #prepareCall(String, List, Map, Provider, Signer)} to avoid
     * {@code null}-arg overload ambiguity.
     */
    public PreparedCall prepareCallWithOptions(
        String methodName,
        List<Object> args,
        CallOptions options,
        Provider provider,
        Signer signer
    ) {
        if (options == null || options.terminalOutputs == null) {
            return prepareCall(
                methodName,
                args,
                options == null ? null : options.newState,
                provider,
                signer
            );
        }
        return prepareTerminalCall(methodName, args, options, provider, signer);
    }

    private PreparedCall prepareTerminalCall(
        String methodName,
        List<Object> args,
        CallOptions options,
        Provider provider,
        Signer signer
    ) {
        if (currentUtxo == null) {
            throw new IllegalStateException(
                "RunarContract.prepareCall: contract has not been deployed."
            );
        }
        RunarArtifact.ABIMethod m = findMethod(methodName);
        if (m == null) {
            throw new IllegalArgumentException(
                "RunarContract.prepareCall: method '" + methodName + "' not found"
            );
        }
        boolean isStateful = artifact.isStateful();
        boolean methodNeedsChange = hasParam(m, "_changePKH");
        boolean methodNeedsNewAmount = hasParam(m, "_newAmount");
        // parentStateful pulls a zero-mutable-field StatefulSmartContract into
        // the OP_PUSH_TX / codesep-aware path so the prepared terminal sighash
        // is computed over the trimmed subscript (issue #44).
        boolean needsOpPushTx = artifact.parentStateful() || isStateful || hasParam(m, "txPreimage");

        // Pre-resolve intent-intrinsic witness hex (throws
        // WitnessValueMissingError if any auto-injected param wasn't set).
        String intentWitnessHex = buildIntentWitnessHex(m);

        // Track Sig placeholders the external signer will fill in.
        List<Object> resolved = new ArrayList<>(args);
        List<Integer> sigIndices = new ArrayList<>();
        for (int i = 0; i < m.params().size() && i < resolved.size(); i++) {
            String type = m.params().get(i).type();
            if ("Sig".equals(type) && resolved.get(i) == null) {
                sigIndices.add(i);
                resolved.set(i, "00".repeat(72));
            }
            if ("PubKey".equals(type) && resolved.get(i) == null && signer != null) {
                resolved.set(i, ScriptUtils.bytesToHex(signer.pubKey()));
            }
            rejectUnresolvableNullArg(
                "RunarContract.prepareTerminalCall", m.params().get(i), i, resolved.get(i));
        }

        // Build the same tx layout as callTerminal: contract input +
        // funding inputs + caller-supplied outputs. No continuation, no
        // change, no automatic funding selection.
        long contractSats = currentUtxo.satoshis();
        // Funding (and terminal fee) inputs are signed by fundingSigner when set
        // (issue #134); the method's own Sig args stay with the connected signer.
        Signer fundingSigner = options.fundingSigner != null ? options.fundingSigner : signer;
        // Fee input (issue #118): a single plain P2PKH UTXO consumed entirely as
        // fee. Prepended to the funding list so it sits at input index 1 (right
        // after the primary contract input) and is signed like any funding input.
        UTXO feeUtxo = options.feeUtxo;
        List<UTXO> callerFunding = options.fundingUtxos == null ? List.of() : options.fundingUtxos;
        List<UTXO> effectiveFunding = new ArrayList<>();
        if (feeUtxo != null) effectiveFunding.add(feeUtxo);
        effectiveFunding.addAll(callerFunding);

        // Sanity: contract balance + funding (incl. any feeUtxo) must cover the
        // output sum; the surplus over outputs becomes the miner fee.
        long termOutSats = 0;
        for (CallOptions.TerminalOutput o : options.terminalOutputs) {
            termOutSats += o.satoshis().longValueExact();
        }
        long fundingSats = 0;
        for (UTXO fu : effectiveFunding) fundingSats += fu.satoshis();
        if (contractSats + fundingSats < termOutSats) {
            throw new IllegalStateException(
                "RunarContract.prepareCall: terminal outputs (" + termOutSats
                    + " sats) exceed contract balance (" + contractSats
                    + ") + funding (" + fundingSats + ")"
            );
        }

        // Sequence (issue #131): all-final inputs make nLockTime a consensus
        // no-op — when a non-zero locktime is set, default to 0xfffffffe so the
        // terminal method's extractLocktime assertion is actually enforced.
        long termSequence = resolveInputSequence(options.locktime, options.sequence);
        // Terminal calls typically assert extractLocktime(preimage) >= deadline.
        // Default 0 preserves legacy behavior for non-locktime contracts.
        int terminalLocktime = options.locktime != null ? options.locktime : 0;
        java.util.function.Supplier<RawTx> buildTx = () -> {
            RawTx t = new RawTx();
            t.locktime = terminalLocktime;
            t.addInput(currentUtxo.txid(), currentUtxo.outputIndex(), "");
            for (UTXO fu : effectiveFunding) {
                t.addInput(fu.txid(), fu.outputIndex(), "");
            }
            for (CallOptions.TerminalOutput o : options.terminalOutputs) {
                t.addOutput(o.satoshis().longValueExact(), o.resolveScriptHex());
            }
            t.setAllSequences(termSequence);
            return t;
        };

        String contractUnlock;
        List<byte[]> sighashes;

        // Issue #123: the method's declared @sighash mode (default 0x41). Threaded
        // into the covenant preimage/sig AND the digest external signers produce.
        int methodSigHash = m.sigHashType() != null ? m.sigHashType() : OpPushTx.SIGHASH_ALL_FORKID;

        if (needsOpPushTx) {
            int methodIndex = findPublicMethodIndex(methodName);
            int codeSepIdx = getCodeSepIndex(methodIndex);
            String fullScriptHex = currentUtxo.scriptHex();
            String sighashSubscript = codeSepIdx >= 0
                ? fullScriptHex.substring((codeSepIdx + 1) * 2)
                : fullScriptHex;

            String placeholderUnlock = buildPushTxUnlock(
                m, methodName, resolved, "00".repeat(72),
                methodNeedsChange ? "00".repeat(20) : null,
                0L, methodNeedsNewAmount, 0L, "00".repeat(181),
                intentWitnessHex
            );
            RawTx tx = buildTx.get();
            tx.setUnlockingScript(0, placeholderUnlock);
            byte[] preimage = OpPushTx.preimage(
                tx, 0, ScriptUtils.hexToBytes(sighashSubscript),
                contractSats, methodSigHash
            );
            byte[] opPushTxSig = OpPushTx.computePushTxSig(
                tx, 0, sighashSubscript, contractSats, methodSigHash
            );
            String opPushTxSigHex = ScriptUtils.bytesToHex(opPushTxSig);
            String preimageHex = ScriptUtils.bytesToHex(preimage);

            // Sighashes the external signer must produce (same digest for
            // every Sig in the contract input — see prepareCall comment).
            byte[] userSighash = sigIndices.isEmpty()
                ? new byte[0]
                : tx.sighashBIP143(
                    0, sighashSubscript, contractSats, methodSigHash
                );
            sighashes = new ArrayList<>(sigIndices.size());
            for (int i = 0; i < sigIndices.size(); i++) sighashes.add(userSighash.clone());

            contractUnlock = buildPushTxUnlock(
                m, methodName, resolved, opPushTxSigHex,
                /*changePkhHex (terminal: no change)*/ null,
                0L, methodNeedsNewAmount, 0L, preimageHex,
                intentWitnessHex
            );
        } else {
            // Pure stateless terminal — finalizeCall splices Sig pushes
            // into the rebuilt unlock.
            String placeholderUnlock = buildUnlockingScript(m, resolved) + intentWitnessHex;
            RawTx tx = buildTx.get();
            tx.setUnlockingScript(0, placeholderUnlock);
            byte[] sh = sigIndices.isEmpty()
                ? new byte[0]
                : tx.sighashBIP143(
                    0, currentUtxo.scriptHex(), contractSats, methodSigHash
                );
            sighashes = new ArrayList<>(sigIndices.size());
            for (int i = 0; i < sigIndices.size(); i++) sighashes.add(sh.clone());
            // placeholderUnlock already includes intent witness suffix; reuse
            // it as the final contract unlock for stateless terminal.
            contractUnlock = placeholderUnlock;
        }

        RawTx finalTx = buildTx.get();
        finalTx.setUnlockingScript(0, contractUnlock);

        // Sign every funding input now (feeUtxo first, at index 1 — issue #118),
        // with fundingSigner (issue #134) — only the contract-input Sig values
        // remain for the external signer to fill in. Each P2PKH BIP-143 sighash
        // covers only hashPrevouts / hashOutputs / its own outpoint — NOT input
        // 0's scriptSig — so it stays valid after finalizeCall rewrites input 0.
        if (fundingSigner != null) {
            for (int i = 0; i < effectiveFunding.size(); i++) {
                int inputIdx = 1 + i;
                UTXO fu = effectiveFunding.get(i);
                byte[] fundSighash = finalTx.sighashBIP143(
                    inputIdx, fu.scriptHex(), fu.satoshis(), RawTx.SIGHASH_ALL_FORKID
                );
                byte[] der = fundingSigner.sign(fundSighash, null);
                String fundSigHex = ScriptUtils.bytesToHex(der)
                    + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
                String fundUnlock = ScriptUtils.encodePushData(fundSigHex)
                    + ScriptUtils.encodePushData(ScriptUtils.bytesToHex(fundingSigner.pubKey()));
                finalTx.setUnlockingScript(inputIdx, fundUnlock);
            }
        }

        // newLockingScriptHex = null + isStateful = false telegraphs the
        // terminal flag to finalizeCall (which clears currentUtxo).
        return new PreparedCall(
            finalTx.toHex(), sighashes, sigIndices,
            methodName, resolved, currentUtxo, /*isStateful*/ false,
            /*continuation*/ null, /*newLockingScriptHex*/ null, /*newSatoshis*/ 0L,
            intentWitnessHex
        );
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

        // Splice real signatures into the resolved-args list. Issue #123: the
        // appended flag byte must match the mode the prepared sighash digest was
        // built under (see prepareTerminalCall), so external signers verify.
        int methodSigHash = m.sigHashType() != null ? m.sigHashType() : RawTx.SIGHASH_ALL_FORKID;
        List<Object> resolved = new ArrayList<>(prepared.resolvedArgs);
        for (int i = 0; i < prepared.sigIndices().size(); i++) {
            int argIdx = prepared.sigIndices().get(i);
            byte[] der = signatures.get(i);
            String sigHex = ScriptUtils.bytesToHex(der)
                + String.format("%02x", methodSigHash & 0xff);
            resolved.set(argIdx, sigHex);
        }
        String unlockHex = buildUnlockingScript(m, resolved) + prepared.intentWitnessHex;

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
        // Append a method-selector push when the contract exposes more
        // than one public method. The compiler emits a router that
        // pops this index off the stack and dispatches accordingly.
        if (countPublicMethods() > 1) {
            int idx = findPublicMethodIndex(m.name());
            sb.append(ContractScript.encodeConstructorArg(
                java.math.BigInteger.valueOf(idx), "bigint"
            ));
        }
        return sb.toString();
    }

    /** Computes the BIP-143 sighash over the first input of a rendered tx. */
    private byte[] computeContractSighash(String txHex, int inputIndex) {
        return computeContractSighash(txHex, inputIndex, RawTx.SIGHASH_ALL_FORKID);
    }

    /** Issue #123: BIP-143 sighash over the first input under a declared mode. */
    private byte[] computeContractSighash(String txHex, int inputIndex, int sigHashType) {
        RawTx parsed = RawTxParser.parse(txHex);
        return parsed.sighashBIP143(inputIndex, currentUtxo.scriptHex(), currentUtxo.satoshis(),
            sigHashType);
    }
}
