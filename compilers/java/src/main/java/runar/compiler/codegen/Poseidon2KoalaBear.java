package runar.compiler.codegen;

import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.StackOp;

/**
 * Poseidon2-over-KoalaBear permutation codegen — <b>Java tier stub,
 * intentionally non-functional</b>.
 *
 * <p>See {@link BabyBear} for the project-policy rationale. Poseidon2 is
 * not user-callable as a top-level Rúnar builtin; it is consumed
 * internally by the Mode-3 STARK/FRI verifier (via Fiat–Shamir) and by
 * the Poseidon2-Merkle builder. The stub is kept for module-presence
 * parity with the other five non-Go tiers.
 *
 * <p>Reference implementations:
 * <ul>
 *   <li>TS: {@code packages/runar-compiler/src/passes/poseidon2-koalabear-codegen.ts}</li>
 *   <li>Rust: {@code compilers/rust/src/codegen/poseidon2_koalabear.rs}</li>
 *   <li>Python: {@code compilers/python/runar_compiler/codegen/poseidon2_koalabear.py}</li>
 *   <li>Zig: {@code compilers/zig/src/passes/helpers/poseidon2_koalabear_emitters.zig}</li>
 *   <li>Ruby: {@code compilers/ruby/lib/runar_compiler/codegen/poseidon2_koalabear.rb}</li>
 * </ul>
 */
public final class Poseidon2KoalaBear {

    private Poseidon2KoalaBear() {}

    /** Poseidon2 state width (number of KoalaBear elements). */
    public static final int POSEIDON2_KB_WIDTH = 16;

    /** Number of full (external) rounds in the SP1 Poseidon2-KB parameter set. */
    public static final int POSEIDON2_KB_EXTERNAL_ROUNDS = 8;

    /** Number of partial (internal) rounds in the SP1 Poseidon2-KB parameter set. */
    public static final int POSEIDON2_KB_INTERNAL_ROUNDS = 20;

    /** Total rounds = external + internal. */
    public static final int POSEIDON2_KB_TOTAL_ROUNDS =
        POSEIDON2_KB_EXTERNAL_ROUNDS + POSEIDON2_KB_INTERNAL_ROUNDS;

    /**
     * Poseidon2-KB has no top-level user-callable builtin. The set is
     * empty; provided for API symmetry with the other modules in this
     * package.
     */
    private static final Set<String> NAMES = Set.of();

    public static boolean isPoseidon2KoalaBearBuiltin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Always throws {@link UnsupportedOperationException}. See {@link BabyBear#dispatch}.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        throw new UnsupportedOperationException(
            "Java tier carries partial port only; builtin '" + funcName
                + "' belongs to the Poseidon2-KoalaBear family which is Go-only by "
                + "conformance policy — see CLAUDE.md (\"Go-only crypto codegen modules\") "
                + "and conformance/README.md (\"Per-fixture compiler allowlist\"). "
                + "Compile this contract with the Go compiler, or opt the fixture "
                + "out of the Java tier via source.json's \"compilers\" allowlist.");
    }
}
