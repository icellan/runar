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
        return ContractScript.renderLockingScript(artifact, constructorArgs, state);
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
