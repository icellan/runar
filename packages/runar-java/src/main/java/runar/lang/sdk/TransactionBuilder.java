package runar.lang.sdk;

import java.util.ArrayList;
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

    // ------------------------------------------------------------------
    // Full call-tx layout (OP_PUSH_TX flow)
    // ------------------------------------------------------------------

    /**
     * Builds a call transaction that funds the fee from a list of P2PKH
     * UTXOs owned by the signer. Used by {@link RunarContract#call} for
     * stateful contracts and stateless OP_PUSH_TX contracts.
     *
     * <p>Layout:
     * <ul>
     *   <li>Input 0: {@code currentUtxo} with the supplied unlocking script.</li>
     *   <li>Inputs 1..n: P2PKH funding UTXOs from {@code additionalUtxos}
     *       (left empty here; the caller signs them after the layout
     *       settles).</li>
     *   <li>Output 0 (optional): contract continuation with
     *       {@code newLockingScriptHex} and {@code newSatoshis} sats.</li>
     *   <li>Output 1 (optional): P2PKH change to the signer's address.</li>
     * </ul>
     *
     * <p>Returns the {@link RawTx} (mutable, for splice-in) plus the
     * computed change amount that must be encoded inside the unlocking
     * script's {@code _changeAmount} push.
     */
    public static CallTxResult buildCallTransactionFull(
        UTXO currentUtxo,
        String unlockingScriptHex,
        String newLockingScriptHex,
        long newSatoshis,
        List<UTXO> additionalUtxos,
        String changeAddress,
        long feeRate
    ) {
        long rate = feeRate > 0 ? feeRate : FeeEstimator.DEFAULT_FEE_RATE;

        // Greedy largest-first selection of P2PKH funding UTXOs to cover
        // the fee. Stateful contracts forward all contract sats to the
        // continuation, so the funding inputs alone pay the fee.
        List<UTXO> sortedFunding = new ArrayList<>(additionalUtxos);
        sortedFunding.sort((a, b) -> Long.compare(b.satoshis(), a.satoshis()));

        long contractIn = currentUtxo.satoshis();
        long contractOutSats = newLockingScriptHex == null
            ? 0
            : (newSatoshis > 0 ? newSatoshis : currentUtxo.satoshis());

        // Always emit a P2PKH change output for the signer; this is the
        // only sink for the funding UTXOs' surplus and matches the Go
        // SDK's stateful-call layout.
        String changeScript = ScriptUtils.buildP2PKHScript(changeAddress);
        int contractInputScriptLen = unlockingScriptHex.length() / 2;
        int[] contractOutputLens = newLockingScriptHex == null
            ? new int[0]
            : new int[] { newLockingScriptHex.length() / 2 };

        List<UTXO> selected = new ArrayList<>();
        long totalFunding = 0;
        long fee;
        long change;
        // Iterate: add UTXOs until inputs cover the contract output +
        // estimated fee with positive change.
        int i = 0;
        while (true) {
            fee = FeeEstimator.estimateCallFee(
                contractInputScriptLen, 0, selected.size(),
                contractOutputLens, /*withChange*/ true, rate
            );
            change = contractIn + totalFunding - contractOutSats - fee;
            if (change >= 0 || i >= sortedFunding.size()) break;
            UTXO next = sortedFunding.get(i++);
            selected.add(next);
            totalFunding += next.satoshis();
        }
        if (change < 0) {
            throw new IllegalStateException(
                "TransactionBuilder.buildCallTransactionFull: insufficient funds: "
                    + "need fee " + fee + " + contract output " + contractOutSats
                    + ", have contract " + contractIn + " + funding " + totalFunding
            );
        }

        RawTx tx = new RawTx();
        tx.addInput(currentUtxo.txid(), currentUtxo.outputIndex(), unlockingScriptHex);
        for (UTXO f : selected) {
            tx.addInput(f.txid(), f.outputIndex(), "");
        }
        if (newLockingScriptHex != null) {
            tx.addOutput(contractOutSats, newLockingScriptHex);
        }
        if (change > 0) {
            tx.addOutput(change, changeScript);
        }
        return new CallTxResult(tx, change, selected);
    }

    /**
     * Result of {@link #buildCallTransactionFull}. {@link #tx()} is
     * mutable so callers can splice in real signatures and unlocking
     * scripts after they've been computed against the laid-out tx.
     */
    public static final class CallTxResult {
        private final RawTx tx;
        private final long changeAmount;
        private final List<UTXO> fundingUtxos;

        CallTxResult(RawTx tx, long changeAmount, List<UTXO> fundingUtxos) {
            this.tx = tx;
            this.changeAmount = changeAmount;
            this.fundingUtxos = List.copyOf(fundingUtxos);
        }

        RawTx tx() { return tx; }
        public long changeAmount() { return changeAmount; }
        public List<UTXO> fundingUtxos() { return fundingUtxos; }
    }
}
