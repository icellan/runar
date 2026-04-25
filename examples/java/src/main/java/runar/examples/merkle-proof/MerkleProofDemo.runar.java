package runar.examples.merkleproof;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.runtime.MockCrypto.merkleRootSha256;
import static runar.lang.runtime.MockCrypto.merkleRootHash256;

/**
 * MerkleProofDemo -- demonstrates Merkle proof verification in Bitcoin
 * Script.
 *
 * <p>Ports {@code examples/python/merkle-proof/MerkleProofDemo.runar.py}
 * to Java. Two built-in functions:
 * <ul>
 *   <li>{@code merkleRootSha256(leaf, proof, index, depth)} -- SHA-256
 *       Merkle root (STARK / FRI).</li>
 *   <li>{@code merkleRootHash256(leaf, proof, index, depth)} -- Hash256
 *       Merkle root (Bitcoin).</li>
 * </ul>
 *
 * <p>Parameters:
 * <ul>
 *   <li>{@code leaf}: 32-byte leaf hash.</li>
 *   <li>{@code proof}: concatenated 32-byte sibling hashes
 *       ({@code depth * 32} bytes).</li>
 *   <li>{@code index}: leaf position (determines left / right at each
 *       level).</li>
 *   <li>{@code depth}: number of tree levels (MUST be a compile-time
 *       constant).</li>
 * </ul>
 *
 * <p>The {@code depth} parameter is consumed at compile time -- the loop
 * is unrolled, producing ~15 opcodes per level. No runtime iteration.
 *
 * <p><b>Note:</b> the Merkle builtins are part of the Go-only crypto
 * family. The Java {@link runar.lang.runtime.MockCrypto} runtime provides
 * the implementations so the contract is exercisable from JUnit, but the
 * Rúnar Java compiler does not yet ship Stack-IR codegen for these
 * operations -- end-to-end conformance for this fixture is exercised via
 * the Go / TS / Rust / Python / Zig / Ruby compilers.
 */
class MerkleProofDemo extends SmartContract {

    ByteString expectedRoot;

    MerkleProofDemo(ByteString expectedRoot) {
        super(expectedRoot);
        this.expectedRoot = expectedRoot;
    }

    /** Verify a SHA-256 Merkle proof at depth 4. */
    @Public
    void verifySha256(ByteString leaf, ByteString proof, Bigint index) {
        ByteString root = merkleRootSha256(leaf, proof, index.value(), Bigint.of(4).value());
        assertThat(root.equals(this.expectedRoot));
    }

    /** Verify a Hash256 Merkle proof at depth 4. */
    @Public
    void verifyHash256(ByteString leaf, ByteString proof, Bigint index) {
        ByteString root = merkleRootHash256(leaf, proof, index.value(), Bigint.of(4).value());
        assertThat(root.equals(this.expectedRoot));
    }
}
