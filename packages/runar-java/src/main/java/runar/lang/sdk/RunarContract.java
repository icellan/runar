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

    /**
     * Internal constructor used by {@link #fromUtxo} / {@link #fromTxId}
     * to re-attach to an existing on-chain UTXO without re-running the
     * constructor-arg pipeline. Constructor args are intentionally
     * empty: the deployed locking script already encodes them, and
     * subsequent calls do not need them re-run through ContractScript.
     */
    private RunarContract(RunarArtifact artifact, UTXO utxo) {
        this.artifact = artifact;
        this.constructorArgs = List.of();
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

        boolean isStateful = artifact.isStateful();

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

        // Auto-merge state updates: explicit caller-supplied stateUpdates
        // win; otherwise the ANF interpreter computes the new state from
        // the contract body. Mirrors the Go/Python SDKs.
        if (isStateful) {
            if (stateUpdates != null) {
                state.putAll(stateUpdates);
            } else if (artifact.anf() != null) {
                Map<String, Object> namedArgs = buildNamedArgs(userParams, args);
                try {
                    Map<String, Object> computed = AnfInterpreter.computeNewState(
                        artifact.anf(), methodName, state, namedArgs, constructorArgs
                    );
                    state.putAll(computed);
                } catch (RuntimeException ignore) {
                    // Best-effort — caller can pre-supply stateUpdates if
                    // the body uses primitives the interpreter can't run.
                }
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
            }
        }

        // Detect injected param shapes: stateful contracts may carry
        // _changePKH / _changeAmount / _newAmount and an OP_PUSH_TX
        // preimage slot. The compiler emits these in a fixed order:
        // [user params...] [_changePKH] [_changeAmount] [_newAmount] [txPreimage].
        boolean methodNeedsChange = hasParam(m, "_changePKH");
        boolean methodNeedsNewAmount = hasParam(m, "_newAmount");
        boolean needsOpPushTx = isStateful || hasParam(m, "txPreimage");

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
        return callWithPushTx(
            m, methodName, resolved, sigIndices,
            methodNeedsChange, methodNeedsNewAmount,
            isStateful, provider, signer
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
        String unlockHex = buildUnlockingScript(m, resolved);

        TransactionBuilder.CallResult result = TransactionBuilder.buildCallTransaction(
            artifact, currentUtxo, unlockHex, null, 0, provider, signer, null
        );
        String txHex = result.txHex();

        if (!sigIndices.isEmpty()) {
            byte[] sighash = computeContractSighash(txHex, 0);
            for (int idx : sigIndices) {
                byte[] der = signer.sign(sighash, null);
                String sigHex = ScriptUtils.bytesToHex(der)
                    + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
                resolved.set(idx, sigHex);
            }
            unlockHex = buildUnlockingScript(m, resolved);
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
     * to pay the fee, splices an {@code _opPushTxSig + preimage}
     * pair into the unlocking script, and broadcasts.
     */
    private CallOutcome callWithPushTx(
        RunarArtifact.ABIMethod m,
        String methodName,
        List<Object> resolved,
        List<Integer> sigIndices,
        boolean methodNeedsChange,
        boolean methodNeedsNewAmount,
        boolean isStateful,
        Provider provider,
        Signer signer
    ) {
        // Continuation output (stateful contracts).
        String newLockingScript = null;
        long newSats = 0;
        if (isStateful) {
            String codePart = ContractScript.extractCodePart(currentUtxo.scriptHex());
            String stateHex = StateSerializer.serialize(artifact.stateFields(), state);
            newLockingScript = codePart + "6a" + stateHex;
            newSats = currentUtxo.satoshis();
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

        // First pass: build a placeholder unlock so we can size the tx,
        // estimate the fee, lay out outputs, and compute the change
        // amount that will be embedded in the real unlock.
        String placeholderUnlock = buildPushTxUnlock(
            m, methodName, resolved, /*opPushTxSigHex*/ "00".repeat(72),
            methodNeedsChange ? changePkhHex : null,
            /*changeAmount*/ 0L, methodNeedsNewAmount, newSats,
            /*preimageHex*/ "00".repeat(181)
        );

        TransactionBuilder.CallTxResult firstPass =
            TransactionBuilder.buildCallTransactionFull(
                currentUtxo, placeholderUnlock, newLockingScript, newSats,
                additional, funderAddress, feeRate
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
            /*preimageHex*/ "00".repeat(181)
        );
        TransactionBuilder.CallTxResult secondPass =
            TransactionBuilder.buildCallTransactionFull(
                currentUtxo, secondPassUnlock, newLockingScript, newSats,
                additional, funderAddress, feeRate
            );
        long finalChangeAmount = secondPass.changeAmount();
        RawTx tx = secondPass.tx();

        // Compute the OP_PUSH_TX (k=1, d=1) signature + the preimage now
        // that the tx layout is settled. The on-chain script re-derives
        // the same sighash from the spliced preimage and verifies the
        // signature against G; if either differs by a single byte the
        // node rejects the spend.
        byte[] preimage = OpPushTx.preimage(
            tx, 0, ScriptUtils.hexToBytes(sighashSubscript),
            currentUtxo.satoshis(), OpPushTx.SIGHASH_ALL_FORKID
        );
        byte[] opPushTxSig = OpPushTx.computePushTxSig(
            tx, 0, sighashSubscript, currentUtxo.satoshis()
        );

        // Sign Sig placeholders against the same code-separator-aware
        // sighash the contract input enforces.
        if (!sigIndices.isEmpty()) {
            byte[] userSighash = tx.sighashBIP143(
                0, sighashSubscript, currentUtxo.satoshis(), RawTx.SIGHASH_ALL_FORKID
            );
            for (int idx : sigIndices) {
                byte[] der = signer.sign(userSighash, null);
                String sigHex = ScriptUtils.bytesToHex(der)
                    + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
                resolved.set(idx, sigHex);
            }
        }

        String finalUnlock = buildPushTxUnlock(
            m, methodName, resolved,
            ScriptUtils.bytesToHex(opPushTxSig),
            methodNeedsChange ? changePkhHex : null,
            finalChangeAmount, methodNeedsNewAmount, newSats,
            ScriptUtils.bytesToHex(preimage)
        );
        tx.setUnlockingScript(0, finalUnlock);

        // Sign each P2PKH funding input (input index >= 1).
        for (int i = 0; i < additional.size(); i++) {
            int inputIdx = 1 + i;
            UTXO u = additional.get(i);
            byte[] fundSighash = tx.sighashBIP143(
                inputIdx, u.scriptHex(), u.satoshis(), RawTx.SIGHASH_ALL_FORKID
            );
            byte[] der = signer.sign(fundSighash, null);
            String fundSigHex = ScriptUtils.bytesToHex(der)
                + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
            String fundUnlock = ScriptUtils.encodePushData(fundSigHex)
                + ScriptUtils.encodePushData(ScriptUtils.bytesToHex(signer.pubKey()));
            tx.setUnlockingScript(inputIdx, fundUnlock);
        }

        String txHex = tx.toHex();
        String txid = provider.broadcastRaw(txHex);

        UTXO nextUtxo = null;
        if (isStateful && newLockingScript != null) {
            nextUtxo = new UTXO(txid, 0, newSats, newLockingScript);
            this.currentUtxo = nextUtxo;
        } else {
            this.currentUtxo = null;
        }
        return new CallOutcome(txid, txHex, nextUtxo);
    }

    /**
     * Builds a full OP_PUSH_TX-style unlocking script:
     *   [_codePart] _opPushTxSig user_args [_changePKH _changeAmount]
     *   [_newAmount] preimage [methodSelector]
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
        String preimageHex
    ) {
        StringBuilder sb = new StringBuilder();

        // _codePart push (only when the method needs change — i.e. the
        // contract continuation references the codePart for hash-outputs).
        if (changePkhHex != null) {
            sb.append(ScriptUtils.encodePushData(getCodePartHex()));
        }

        // _opPushTxSig push.
        sb.append(ScriptUtils.encodePushData(opPushTxSigHex));

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

    private int findPublicMethodIndex(String methodName) {
        int i = 0;
        for (RunarArtifact.ABIMethod m : artifact.abi().methods()) {
            if (!m.isPublic()) continue;
            if (m.name().equals(methodName)) return i;
            i++;
        }
        return -1;
    }

    private int getCodeSepIndex(int methodIndex) {
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

    /** Returns user-facing params (skips compiler-injected implicit params for stateful methods). */
    private static List<RunarArtifact.ABIParam> userParams(RunarArtifact.ABIMethod m, boolean isStateful) {
        if (!isStateful) return m.params();
        List<RunarArtifact.ABIParam> out = new ArrayList<>();
        for (RunarArtifact.ABIParam p : m.params()) {
            String n = p.name();
            String t = p.type();
            if ("SigHashPreimage".equals(t)) continue;
            if ("_changePKH".equals(n) || "_changeAmount".equals(n) || "_newAmount".equals(n)) continue;
            out.add(p);
        }
        return out;
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
        RawTx parsed = RawTxParser.parse(txHex);
        return parsed.sighashBIP143(inputIndex, currentUtxo.scriptHex(), currentUtxo.satoshis(),
            RawTx.SIGHASH_ALL_FORKID);
    }
}
