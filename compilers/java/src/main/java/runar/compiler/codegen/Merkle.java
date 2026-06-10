package runar.compiler.codegen;

import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.StackOp;

/**
 * Merkle root verification codegen — <b>Java tier stub for the
 * Go-only {@code merkleRootSha256} builtin, intentionally
 * non-functional</b>.
 *
 * <p>CLAUDE.md ("Go-only crypto codegen modules") places
 * {@code merkleRootSha256} in the Go-only Mode-3 STARK / FRI verifier
 * family (single-SHA-256 Merkle is the standard inside STARK proofs).
 * Standard double-SHA-256 Bitcoin Merkle ({@code merkleRootHash256})
 * is <b>not</b> listed by this stub and is intentionally not routed
 * here — see {@code BuiltinRegistry} for its registration; if the
 * Java tier ever needs it the work is to add a real emitter, not a
 * stub.
 *
 * <p>The stub is kept for module-presence parity with the other five
 * non-Go tiers.
 *
 * <p>Reference implementations:
 * <ul>
 *   <li>TS: {@code packages/runar-compiler/src/passes/merkle-codegen.ts}</li>
 *   <li>Rust: {@code compilers/rust/src/codegen/merkle.rs}</li>
 *   <li>Python: {@code compilers/python/runar_compiler/codegen/merkle.py}</li>
 *   <li>Zig: {@code compilers/zig/src/passes/helpers/merkle_emitters.zig}</li>
 *   <li>Ruby: {@code compilers/ruby/lib/runar_compiler/codegen/merkle.rb}</li>
 * </ul>
 */
public final class Merkle {

    private Merkle() {}

    /** Minimum supported tree depth. */
    public static final int MIN_DEPTH = 1;

    /** Maximum supported tree depth (matches the Rust/Go reference). */
    public static final int MAX_DEPTH = 32;

    /**
     * Builtin names that route through {@link #dispatch}. Only the
     * Go-only single-SHA-256 variant is listed; {@code merkleRootHash256}
     * is intentionally excluded — see class-level docs.
     */
    private static final Set<String> NAMES = Set.of(
        "merkleRootSha256"
    );

    public static boolean isMerkleBuiltin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Always throws {@link UnsupportedOperationException}. See {@link BabyBear#dispatch}.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        throw new UnsupportedOperationException(
            "Java tier carries partial port only; builtin '" + funcName
                + "' belongs to the sha256-Merkle family which is Go-only by "
                + "conformance policy — see CLAUDE.md (\"Go-only crypto codegen modules\") "
                + "and conformance/README.md (\"Per-fixture compiler allowlist\"). "
                + "Compile this contract with the Go compiler, or opt the fixture "
                + "out of the Java tier via source.json's \"compilers\" allowlist.");
    }
}
