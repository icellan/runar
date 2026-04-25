package runar.examples.statecovenant;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.hash256;
import static runar.lang.runtime.MockCrypto.bbFieldMul;
import static runar.lang.runtime.MockCrypto.merkleRootSha256;

/**
 * StateCovenant -- a stateful UTXO chain covenant that guards a state
 * root.
 *
 * <p>Ports {@code examples/python/state-covenant/StateCovenant.runar.py}
 * to Java.
 *
 * <p>Demonstrates the core pattern for a validity-proof-based state
 * covenant: each spend advances the state by providing a new state root,
 * a block number, and proof data. The covenant verifies the proof and
 * enforces monotonic block number progression.
 *
 * <p>This contract exercises the key primitives needed for STARK / FRI
 * verification on BSV: Baby Bear field arithmetic, SHA-256 Merkle proof
 * verification, and {@code hash256} batch data binding -- without
 * implementing the full FRI verifier.
 *
 * <p><b>Note:</b> the Baby Bear and Merkle builtins are part of the
 * Go-only crypto family. The Java SDK exposes runtime implementations
 * via {@link runar.lang.runtime.MockCrypto} so the contract is
 * exercisable from the simulator, but the Rúnar Java compiler does not
 * yet ship Stack-IR codegen for them -- end-to-end conformance for this
 * fixture is exercised through the other compiler tiers via the shared
 * conformance suite.
 */
class StateCovenant extends StatefulSmartContract {

    ByteString stateRoot;
    Bigint blockNumber;
    @Readonly ByteString verifyingKeyHash;

    StateCovenant(ByteString stateRoot, Bigint blockNumber, ByteString verifyingKeyHash) {
        super(stateRoot, blockNumber, verifyingKeyHash);
        this.stateRoot = stateRoot;
        this.blockNumber = blockNumber;
        this.verifyingKeyHash = verifyingKeyHash;
    }

    /**
     * Advance the covenant state. Verifies proof data and updates state
     * root and block number.
     */
    @Public
    void advanceState(
        ByteString newStateRoot,
        Bigint newBlockNumber,
        ByteString batchDataHash,
        ByteString preStateRoot,
        Bigint proofFieldA,
        Bigint proofFieldB,
        Bigint proofFieldC,
        ByteString merkleLeaf,
        ByteString merkleProof,
        Bigint merkleIndex
    ) {
        // 1. Block number must strictly increase.
        assertThat(newBlockNumber.gt(this.blockNumber));

        // 2. Pre-state root must match current covenant state.
        assertThat(preStateRoot.equals(this.stateRoot));

        // 3. Verify Baby Bear field multiplication (simplified proof check).
        assertThat(bbFieldMul(proofFieldA.value(), proofFieldB.value()).equals(proofFieldC.value()));

        // 4. Verify Merkle commitment: the leaf must be in a SHA-256 tree
        //    whose root matches the verifying key hash.
        ByteString computedRoot = merkleRootSha256(merkleLeaf, merkleProof, merkleIndex.value(), Bigint.of(4).value());
        assertThat(computedRoot.equals(this.verifyingKeyHash));

        // 5. Batch data hash binding: verify the caller provided the correct
        //    hash256 of the state transition.
        ByteString expectedBatchHash = hash256(cat(preStateRoot, newStateRoot));
        assertThat(batchDataHash.equals(expectedBatchHash));

        // 6. Update state -- compiler auto-enforces output carries new state.
        this.stateRoot = newStateRoot;
        this.blockNumber = newBlockNumber;
    }
}
