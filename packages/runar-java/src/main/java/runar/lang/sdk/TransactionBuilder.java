package runar.lang.sdk;

import java.util.List;
import java.util.Map;

/**
 * Builds deploy and call transactions. Parity target:
 * {@code packages/runar-go/sdk_deployment.go} and
 * {@code packages/runar-go/sdk_calling.go}.
 *
 * <p>M8 scope:
 * <ul>
 *   <li>{@link #buildDeployTransaction} — signs P2PKH funding inputs,
 *       emits the contract output and a P2PKH change output, returns
 *       the fully-serialised hex transaction.</li>
 *   <li>{@link #buildCallTransaction} — builds a minimal call tx
 *       spending a stateless contract UTXO. Stateful multi-output
 *       continuations, OP_PUSHTX preimage injection, and multi-signer
 *       prepare/finalize flows land in M9.</li>
 * </ul>
 */
public final class TransactionBuilder {

    private TransactionBuilder() {}

    // ------------------------------------------------------------------
    // Deploy
    // ------------------------------------------------------------------

    /**
     * Builds, signs, and serialises a deploy transaction. Splices
     * constructor args into the artifact template and outputs
     * {@code satoshis} to that locking script. Any remaining input
     * value (minus fees) goes to {@code changeAddress}.
     */
    public static DeployResult buildDeployTransaction(
        RunarArtifact artifact,
        List<Object> constructorArgs,
        Provider provider,
        Signer signer,
        long satoshis,
        String changeAddress
    ) {
        String lockingScript = ContractScript.renderLockingScript(artifact, constructorArgs, null);
        return buildDeployWithLockingScript(lockingScript, provider, signer, satoshis, changeAddress);
    }

    /** Lower-level entry: skip the artifact splice and use a prebuilt locking script. */
    public static DeployResult buildDeployWithLockingScript(
        String lockingScriptHex,
        Provider provider,
        Signer signer,
        long satoshis,
        String changeAddress
    ) {
        String funderAddress = signer.address();
        List<UTXO> all = provider.listUtxos(funderAddress);
        if (all.isEmpty()) {
            throw new IllegalStateException(
                "TransactionBuilder.buildDeployTransaction: no UTXOs for address " + funderAddress
            );
        }
        long feeRate = provider.getFeeRate();
        int scriptLen = lockingScriptHex.length() / 2;
        List<UTXO> selected = UtxoSelector.selectLargestFirst(all, satoshis, scriptLen, feeRate);

        long total = 0;
        for (UTXO u : selected) total += u.satoshis();
        long fee = FeeEstimator.estimateDeployFee(selected.size(), scriptLen, feeRate);
        long change = total - satoshis - fee;
        if (change < 0) {
            throw new IllegalStateException(
                "TransactionBuilder.buildDeployTransaction: insufficient funds: need "
                    + (satoshis + fee) + ", have " + total
            );
        }

        RawTx tx = new RawTx();
        for (UTXO u : selected) tx.addInput(u.txid(), u.outputIndex(), "");
        tx.addOutput(satoshis, lockingScriptHex);
        String effectiveChangeAddr = (changeAddress == null || changeAddress.isEmpty())
            ? funderAddress
            : changeAddress;
        if (change > 0) {
            tx.addOutput(change, ScriptUtils.buildP2PKHScript(effectiveChangeAddr));
        }

        // Sign each P2PKH funding input.
        for (int i = 0; i < selected.size(); i++) {
            UTXO u = selected.get(i);
            byte[] sighash = tx.sighashBIP143(i, u.scriptHex(), u.satoshis(), RawTx.SIGHASH_ALL_FORKID);
            byte[] der = signer.sign(sighash, null);
            byte[] pub = signer.pubKey();
            String sigHex = ScriptUtils.bytesToHex(der)
                + String.format("%02x", RawTx.SIGHASH_ALL_FORKID);
            String unlockHex = ScriptUtils.encodePushData(sigHex)
                + ScriptUtils.encodePushData(ScriptUtils.bytesToHex(pub));
            tx.setUnlockingScript(i, unlockHex);
        }

        return new DeployResult(tx.toHex(), lockingScriptHex, selected);
    }

    public record DeployResult(String txHex, String lockingScriptHex, List<UTXO> spentInputs) {}

    // ------------------------------------------------------------------
    // Call
    // ------------------------------------------------------------------

    /**
     * Builds a minimal call transaction that spends {@code contractUtxo}
     * and optionally produces a new contract output with updated state.
     *
     * <p>The unlocking script is produced by the caller (or future
     * {@link ContractScript} helpers) and passed via
     * {@code unlockingScriptHex}. Sig placeholders inside the unlocking
     * script are the caller's responsibility — this builder only frames
     * the transaction and attaches a signed funding input if required.
     */
    public static CallResult buildCallTransaction(
        RunarArtifact artifact,
        UTXO contractUtxo,
        String unlockingScriptHex,
        Map<String, Object> stateUpdates,
        long newContractSatoshis,
        Provider provider,
        Signer signer,
        String changeAddress
    ) {
        RawTx tx = new RawTx();
        tx.addInput(contractUtxo.txid(), contractUtxo.outputIndex(), unlockingScriptHex);

        String newLockingScript = null;
        if (artifact.isStateful() && stateUpdates != null) {
            String codePart = ContractScript.extractCodePart(contractUtxo.scriptHex());
            String stateHex = StateSerializer.serialize(artifact.stateFields(), stateUpdates);
            newLockingScript = codePart + "6a" + stateHex;
            long sats = newContractSatoshis > 0 ? newContractSatoshis : contractUtxo.satoshis();
            tx.addOutput(sats, newLockingScript);
        }

        long feeRate = provider.getFeeRate();
        int contractInputScriptLen = unlockingScriptHex.length() / 2;
        int[] outScriptLens = newLockingScript == null
            ? new int[0]
            : new int[] { newLockingScript.length() / 2 };

        // No P2PKH funding input for M8 scope (stateless-call). Change
        // is whatever contract UTXO leaves over — fee is charged from
        // the contract balance when its output is replaced.
        long fee = FeeEstimator.estimateCallFee(
            contractInputScriptLen, 0, 0, outScriptLens, false, feeRate
        );

        // Optional P2PKH change when the contract output is not rewritten.
        // (Stateless-contract call: contract is fully spent.)
        if (newLockingScript == null) {
            long change = contractUtxo.satoshis() - fee;
            if (change < 0) {
                throw new IllegalStateException(
                    "TransactionBuilder.buildCallTransaction: insufficient contract balance: "
                        + "need fee " + fee + ", have " + contractUtxo.satoshis()
                );
            }
            if (change > 0) {
                String addr = (changeAddress == null || changeAddress.isEmpty())
                    ? signer.address()
                    : changeAddress;
                tx.addOutput(change, ScriptUtils.buildP2PKHScript(addr));
            }
        }

        return new CallResult(tx.toHex(), newLockingScript);
    }

    public record CallResult(String txHex, String newLockingScriptHex) {}
}
