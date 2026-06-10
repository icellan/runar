package runar.compiler.codegen;

import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.StackOp;

/**
 * Poseidon2-Merkle root builder — <b>Java tier stub, intentionally
 * non-functional</b>.
 *
 * <p>This module emits {@code merkleRootPoseidon2KB(leaves...)} for the
 * Mode-3 STARK / FRI verifier. See {@link BabyBear} for the
 * project-policy rationale; the stub is kept for module-presence parity
 * with the other five non-Go tiers.
 *
 * <p>Reference implementations:
 * <ul>
 *   <li>TS: {@code packages/runar-compiler/src/passes/poseidon2-merkle-codegen.ts}</li>
 *   <li>Rust: {@code compilers/rust/src/codegen/poseidon2_merkle.rs}</li>
 *   <li>Python: {@code compilers/python/runar_compiler/codegen/poseidon2_merkle.py}</li>
 *   <li>Zig: {@code compilers/zig/src/passes/helpers/poseidon2_merkle_emitters.zig}</li>
 *   <li>Ruby: {@code compilers/ruby/lib/runar_compiler/codegen/poseidon2_merkle.rb}</li>
 * </ul>
 */
public final class Poseidon2Merkle {

    private Poseidon2Merkle() {}

    /** Minimum supported tree depth. */
    public static final int MIN_DEPTH = 1;

    /** Maximum supported tree depth (matches the Rust/Go reference). */
    public static final int MAX_DEPTH = 32;

    /** Builtin names that route through {@link #dispatch}. */
    private static final Set<String> NAMES = Set.of(
        "merkleRootPoseidon2KB"
    );

    public static boolean isPoseidon2MerkleBuiltin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Always throws {@link UnsupportedOperationException}. See {@link BabyBear#dispatch}.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        throw new UnsupportedOperationException(
            "Java tier carries partial port only; builtin '" + funcName
                + "' belongs to the Poseidon2-Merkle family which is Go-only by "
                + "conformance policy — see CLAUDE.md (\"Go-only crypto codegen modules\") "
                + "and conformance/README.md (\"Per-fixture compiler allowlist\"). "
                + "Compile this contract with the Go compiler, or opt the fixture "
                + "out of the Java tier via source.json's \"compilers\" allowlist.");
    }
}
