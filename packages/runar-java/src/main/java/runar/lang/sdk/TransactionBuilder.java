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
        return buildDeployWithLockingScript(
            lockingScriptHex, provider, signer, satoshis, changeAddress, signer
        );
    }

    /**
     * Deploy variant that signs the P2PKH funding inputs with a separate
     * {@code fundingSigner} (issue #134). The funding-UTXO lookup and the
     * default change address still come from the deploy {@code signer}
     * (mirroring the TS SDK's {@code DeployOptions.fundingSigner}); only the
     * per-input signature + pushed pubkey use {@code fundingSigner}. Pass
     * {@code fundingSigner == signer} for the default (zero behaviour change).
     */
    public static DeployResult buildDeployWithLockingScript(
        String lockingScriptHex,
        Provider provider,
        Signer signer,
        long satoshis,
        String changeAddress,
        Signer fundingSigner
    ) {
        Signer funder = fundingSigner != null ? fundingSigner : signer;
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

        // Sign each P2PKH funding input (with fundingSigner — issue #134).
        for (int i = 0; i < selected.size(); i++) {
            UTXO u = selected.get(i);
            byte[] sighash = tx.sighashBIP143(i, u.scriptHex(), u.satoshis(), RawTx.SIGHASH_ALL_FORKID);
            byte[] der = funder.sign(sighash, null);
            byte[] pub = funder.pubKey();
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
        return buildCallTransactionFull(
            currentUtxo, unlockingScriptHex, newLockingScriptHex,
            newSatoshis, List.of(), additionalUtxos, changeAddress, feeRate
        );
    }

    /**
     * Variant that emits {@code dataOutputs} (from {@code this.addDataOutput(...)})
     * after the state continuation and before the change output, matching
     * the order the compile-time hashOutputs check expects (and the
     * Go/Rust/Python/TS SDKs' layout).
     */
    public static CallTxResult buildCallTransactionFull(
        UTXO currentUtxo,
        String unlockingScriptHex,
        String newLockingScriptHex,
        long newSatoshis,
        List<DataOutput> dataOutputs,
        List<UTXO> additionalUtxos,
        String changeAddress,
        long feeRate
    ) {
        return buildCallTransactionFull(
            currentUtxo, unlockingScriptHex, newLockingScriptHex, newSatoshis,
            dataOutputs, additionalUtxos, changeAddress, feeRate, 0
        );
    }

    /**
     * Variant that additionally sets the tx's nLockTime field. {@code locktime}
     * defaults to 0 (legacy) via the overloads above; pass a non-zero value
     * for contracts that assert {@code extractLocktime(preimage) >= deadline}
     * (e.g. auction close/claim).
     */
    public static CallTxResult buildCallTransactionFull(
        UTXO currentUtxo,
        String unlockingScriptHex,
        String newLockingScriptHex,
        long newSatoshis,
        List<DataOutput> dataOutputs,
        List<UTXO> additionalUtxos,
        String changeAddress,
        long feeRate,
        int locktime
    ) {
        return buildCallTransactionFull(
            currentUtxo, unlockingScriptHex, newLockingScriptHex, newSatoshis,
            dataOutputs, additionalUtxos, changeAddress, feeRate, locktime, null
        );
    }

    /**
     * Multi-contract-input overload: spends {@code currentUtxo} plus every
     * entry of {@code extraContractInputs}, which are placed at input indices
     * {@code 1..N} ahead of the P2PKH funding inputs. Their satoshis count as
     * input value and their serialized bytes count toward the fee, so a merge
     * neither under-funds nor over-selects.
     */
    public static CallTxResult buildCallTransactionFull(
        UTXO currentUtxo,
        String unlockingScriptHex,
        String newLockingScriptHex,
        long newSatoshis,
        List<DataOutput> dataOutputs,
        List<UTXO> additionalUtxos,
        String changeAddress,
        long feeRate,
        int locktime,
        List<ContractInput> extraContractInputs
    ) {
        long rate = feeRate > 0 ? feeRate : FeeEstimator.DEFAULT_FEE_RATE;
        if (dataOutputs == null) dataOutputs = List.of();
        if (extraContractInputs == null) extraContractInputs = List.of();

        // Greedy largest-first selection of P2PKH funding UTXOs to cover
        // the fee. Stateful contracts forward all contract sats to the
        // continuation, so the funding inputs alone pay the fee.
        List<UTXO> sortedFunding = new ArrayList<>(additionalUtxos);
        sortedFunding.sort((a, b) -> Long.compare(b.satoshis(), a.satoshis()));

        // Every contract input contributes value, not just the primary one, so
        // a merge is not over-funded. It does NOT let a merge skip funding:
        // see the selection loop below (N-292).
        long contractIn = currentUtxo.satoshis();
        for (ContractInput ci : extraContractInputs) contractIn += ci.utxo().satoshis();
        long contractOutSats = newLockingScriptHex == null
            ? 0
            : (newSatoshis > 0 ? newSatoshis : currentUtxo.satoshis());
        long dataOutSats = 0;
        for (DataOutput d : dataOutputs) dataOutSats += d.satoshis();

        // Always emit a P2PKH change output for the signer; this is the
        // only sink for the funding UTXOs' surplus and matches the Go
        // SDK's stateful-call layout.
        String changeScript = ScriptUtils.buildP2PKHScript(changeAddress);
        int contractInputScriptLen = unlockingScriptHex.length() / 2;
        // Build the contract-output script-length array including data
        // outputs so fee estimation accounts for their bytes.
        int contractOutCount = newLockingScriptHex == null ? 0 : 1;
        int[] contractOutputLens = new int[contractOutCount + dataOutputs.size()];
        if (contractOutCount == 1) {
            contractOutputLens[0] = newLockingScriptHex.length() / 2;
        }
        for (int j = 0; j < dataOutputs.size(); j++) {
            contractOutputLens[contractOutCount + j] = dataOutputs.get(j).scriptHex().length() / 2;
        }

        List<UTXO> selected = new ArrayList<>();
        long totalFunding = 0;
        long fee;
        long change;
        // Iterate: add UTXOs until inputs cover the contract output +
        // estimated fee with positive change.
        int extraInputBytes = extraContractInputBytes(extraContractInputs);
        int i = 0;
        while (true) {
            fee = FeeEstimator.estimateCallFee(
                contractInputScriptLen, extraInputBytes, selected.size(),
                contractOutputLens, /*withChange*/ true, rate
            );
            change = contractIn + totalFunding - contractOutSats - dataOutSats - fee;
            // N-292 (TS parity): TS's selectUtxos takes the largest candidate
            // BEFORE testing coverage, so whenever funding UTXOs exist at least
            // one is spent and the fee comes from it — never from surplus
            // contract-input value (a merge whose second contract input covers
            // the fee would otherwise build a different tx than every other
            // tier). With no candidates (issue #116 exact-cover) nothing changes.
            if ((change >= 0 && !selected.isEmpty()) || i >= sortedFunding.size()) break;
            UTXO next = sortedFunding.get(i++);
            selected.add(next);
            totalFunding += next.satoshis();
        }
        // Fail closed only when the inputs cannot cover the (non-change)
        // contract + data outputs — the tx would spend more than it takes in
        // and can never confirm (finding C3). Do NOT reject merely because
        // change < 0: an exact-cover continuation (issue #116) keeps the full
        // input value and adds no funding, so change == -fee (negative) even
        // though the zero-fee tx is valid and the covenant accepts a no-change
        // spend. Mirrors TS/Go/Rust/Python/Zig/Ruby
        // (`totalInput < contractOutputSats`); the change output is still
        // omitted below whenever change is not positive.
        if (contractIn + totalFunding < contractOutSats + dataOutSats) {
            throw new IllegalStateException(
                "TransactionBuilder.buildCallTransactionFull: insufficient funds: "
                    + "need fee " + fee + " + contract output " + contractOutSats
                    + " + data outputs " + dataOutSats
                    + ", have contract " + contractIn + " + funding " + totalFunding
            );
        }

        RawTx tx = new RawTx();
        // Locktime: default 0 (legacy); overridable via CallOptions.locktime
        // for contracts asserting extractLocktime(preimage) >= deadline.
        tx.locktime = locktime;
        tx.addInput(currentUtxo.txid(), currentUtxo.outputIndex(), unlockingScriptHex);
        // Extra contract inputs occupy indices 1..N, ahead of every funding
        // input, so the covenant's allPrevouts ordering is stable.
        for (ContractInput ci : extraContractInputs) {
            tx.addInput(ci.utxo().txid(), ci.utxo().outputIndex(),
                ci.unlockingScriptHex() == null ? "" : ci.unlockingScriptHex());
        }
        for (UTXO f : selected) {
            tx.addInput(f.txid(), f.outputIndex(), "");
        }
        if (newLockingScriptHex != null) {
            tx.addOutput(contractOutSats, newLockingScriptHex);
        }
        // Data outputs (from this.addDataOutput in the method body), in
        // declaration order, between the state continuation and the
        // change output. This matches the Go/Rust/Python/TS SDKs and the
        // compile-time hashOutputs check the contract enforces.
        for (DataOutput d : dataOutputs) {
            tx.addOutput(d.satoshis(), d.scriptHex());
        }
        if (change > 0) {
            tx.addOutput(change, changeScript);
        }
        // Report 0 (not the negative estimate) when no change output was
        // emitted — TS/Go clamp the same way, and the reported amount is
        // spliced into the unlocking script by RunarContract.call.
        return new CallTxResult(tx, change > 0 ? change : 0, selected);
    }

    /**
     * Finding G1 variant: emits an ORDERED list of contract (state-class)
     * outputs — the state continuation interleaved with
     * {@code this.addRawOutput(...)} raw outputs — in the exact SOURCE order
     * the on-chain covenant folds them into {@code hashOutputs}, followed by
     * {@code dataOutputs} and then change.
     *
     * <p>Used only when a stateful method calls {@code this.addRawOutput(...)}:
     * the single-continuation {@link #buildCallTransactionFull} overloads emit
     * the state output alone, so the built tx would mismatch {@code hashOutputs}
     * and input 0's state-check OP_VERIFY would reject (funds stranded).
     * {@code contractOutputs} must contain exactly the state-class outputs the
     * ANF interpreter surfaced, in order (raw entries carry their own script;
     * the state entry carries the freshly computed continuation locking script).
     *
     * <p>Layout mirrors the single-continuation path
     * ({@code [contractOutputs...][dataOutputs][change]}) and reuses the same
     * two-pass fee/coin-selection logic, so a 1-element (state-only) list would
     * be byte-identical to the legacy path.
     */
    public static CallTxResult buildCallTransactionFullOrdered(
        UTXO currentUtxo,
        String unlockingScriptHex,
        List<ContractOutput> contractOutputs,
        List<DataOutput> dataOutputs,
        List<UTXO> additionalUtxos,
        String changeAddress,
        long feeRate,
        int locktime
    ) {
        return buildCallTransactionFullOrdered(
            currentUtxo, unlockingScriptHex, contractOutputs, dataOutputs,
            additionalUtxos, changeAddress, feeRate, locktime, null
        );
    }

    /** Multi-contract-input variant of the ordered builder (see the
     *  {@link #buildCallTransactionFull} overload for the semantics). */
    public static CallTxResult buildCallTransactionFullOrdered(
        UTXO currentUtxo,
        String unlockingScriptHex,
        List<ContractOutput> contractOutputs,
        List<DataOutput> dataOutputs,
        List<UTXO> additionalUtxos,
        String changeAddress,
        long feeRate,
        int locktime,
        List<ContractInput> extraContractInputs
    ) {
        long rate = feeRate > 0 ? feeRate : FeeEstimator.DEFAULT_FEE_RATE;
        if (dataOutputs == null) dataOutputs = List.of();
        if (contractOutputs == null) contractOutputs = List.of();
        if (extraContractInputs == null) extraContractInputs = List.of();

        List<UTXO> sortedFunding = new ArrayList<>(additionalUtxos);
        sortedFunding.sort((a, b) -> Long.compare(b.satoshis(), a.satoshis()));

        long contractIn = currentUtxo.satoshis();
        for (ContractInput ci : extraContractInputs) contractIn += ci.utxo().satoshis();
        long contractOutSats = 0;
        for (ContractOutput c : contractOutputs) contractOutSats += c.satoshis();
        long dataOutSats = 0;
        for (DataOutput d : dataOutputs) dataOutSats += d.satoshis();

        String changeScript = ScriptUtils.buildP2PKHScript(changeAddress);
        int contractInputScriptLen = unlockingScriptHex.length() / 2;
        // Fee estimation must account for every contract output + data output.
        int[] contractOutputLens = new int[contractOutputs.size() + dataOutputs.size()];
        for (int j = 0; j < contractOutputs.size(); j++) {
            contractOutputLens[j] = contractOutputs.get(j).scriptHex().length() / 2;
        }
        for (int j = 0; j < dataOutputs.size(); j++) {
            contractOutputLens[contractOutputs.size() + j] = dataOutputs.get(j).scriptHex().length() / 2;
        }

        List<UTXO> selected = new ArrayList<>();
        long totalFunding = 0;
        long fee;
        long change;
        int extraInputBytes = extraContractInputBytes(extraContractInputs);
        int i = 0;
        while (true) {
            fee = FeeEstimator.estimateCallFee(
                contractInputScriptLen, extraInputBytes, selected.size(),
                contractOutputLens, /*withChange*/ true, rate
            );
            change = contractIn + totalFunding - contractOutSats - dataOutSats - fee;
            // N-292 (TS parity): TS's selectUtxos takes the largest candidate
            // BEFORE testing coverage, so whenever funding UTXOs exist at least
            // one is spent and the fee comes from it — never from surplus
            // contract-input value (a merge whose second contract input covers
            // the fee would otherwise build a different tx than every other
            // tier). With no candidates (issue #116 exact-cover) nothing changes.
            if ((change >= 0 && !selected.isEmpty()) || i >= sortedFunding.size()) break;
            UTXO next = sortedFunding.get(i++);
            selected.add(next);
            totalFunding += next.satoshis();
        }
        // Same fail-closed condition as buildCallTransactionFull (finding C3):
        // reject only when the inputs cannot cover the non-change outputs, so
        // an exact-cover / zero-fee continuation (issue #116) still builds.
        if (contractIn + totalFunding < contractOutSats + dataOutSats) {
            throw new IllegalStateException(
                "TransactionBuilder.buildCallTransactionFullOrdered: insufficient funds: "
                    + "need fee " + fee + " + contract outputs " + contractOutSats
                    + " + data outputs " + dataOutSats
                    + ", have contract " + contractIn + " + funding " + totalFunding
            );
        }

        RawTx tx = new RawTx();
        tx.locktime = locktime;
        tx.addInput(currentUtxo.txid(), currentUtxo.outputIndex(), unlockingScriptHex);
        // Extra contract inputs occupy indices 1..N, ahead of every funding
        // input, so the covenant's allPrevouts ordering is stable.
        for (ContractInput ci : extraContractInputs) {
            tx.addInput(ci.utxo().txid(), ci.utxo().outputIndex(),
                ci.unlockingScriptHex() == null ? "" : ci.unlockingScriptHex());
        }
        for (UTXO f : selected) {
            tx.addInput(f.txid(), f.outputIndex(), "");
        }
        // Contract (state-class) outputs in source order (finding G1).
        for (ContractOutput c : contractOutputs) {
            tx.addOutput(c.satoshis(), c.scriptHex());
        }
        // Data outputs after all state-class outputs, then change.
        for (DataOutput d : dataOutputs) {
            tx.addOutput(d.satoshis(), d.scriptHex());
        }
        if (change > 0) {
            tx.addOutput(change, changeScript);
        }
        // Report 0 (not the negative estimate) when no change output was
        // emitted — TS/Go clamp the same way, and the reported amount is
        // spliced into the unlocking script by RunarContract.call.
        return new CallTxResult(tx, change > 0 ? change : 0, selected);
    }

    /**
     * One transaction output emitted from {@code this.addDataOutput(...)}.
     * {@code scriptHex} is the raw hex-encoded scriptPubKey bytes (caller
     * already includes any {@code OP_RETURN} / {@code OP_FALSE OP_RETURN}
     * prefix it wants).
     */
    public record DataOutput(long satoshis, String scriptHex) {}

    /**
     * One state-class contract output for the ordered call path (finding G1):
     * either the state continuation ({@code scriptHex} = the fresh continuation
     * locking script) or a {@code this.addRawOutput(...)} raw output
     * ({@code scriptHex} = the caller-supplied raw locking script). Emitted in
     * source order by {@link #buildCallTransactionFullOrdered}.
     */
    public record ContractOutput(long satoshis, String scriptHex) {}

    /**
     * An extra contract UTXO spent alongside the primary one, with the
     * unlocking script that spends it. Placed at input index {@code 1..N},
     * ahead of every P2PKH funding input, so the covenant's
     * {@code allPrevouts} ordering is stable and predictable.
     *
     * <p>Its satoshis count toward the transaction's input value, so a merge
     * funds its own continuation.
     */
    public record ContractInput(UTXO utxo, String unlockingScriptHex) {}

    /**
     * Total serialized size, in bytes, of a set of extra contract inputs:
     * {@code 32 (outpoint txid) + 4 (vout) + varint(scriptLen) + scriptLen
     * + 4 (sequence)} each. Feeds
     * {@link FeeEstimator#estimateCallFee}'s {@code extraContractInputsScriptLen}
     * slot, which expects an already-summed total.
     */
    static int extraContractInputBytes(List<ContractInput> extras) {
        if (extras == null) return 0;
        int total = 0;
        for (ContractInput ci : extras) {
            int scriptLen = ci.unlockingScriptHex() == null ? 0 : ci.unlockingScriptHex().length() / 2;
            total += 32 + 4 + FeeEstimator.varIntByteSize(scriptLen) + scriptLen + 4;
        }
        return total;
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
