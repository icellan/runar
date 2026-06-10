package runar.compiler.codegen;

import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.StackOp;

/**
 * Fiat–Shamir transcript codegen over KoalaBear (duplex sponge built
 * on Poseidon2-KB) plus the SP1 FRI verifier driver — <b>Java tier
 * stub, intentionally non-functional</b>.
 *
 * <p>See {@link BabyBear} for the project-policy rationale. The
 * Fiat–Shamir transcript has no top-level Rúnar builtin (it is driven
 * by the FRI verifier); {@code verifySP1FRI} is the user-facing
 * Mode-3 entry point that consumes it. The stub is kept for
 * module-presence parity with the other five non-Go tiers.
 *
 * <p>Reference implementations:
 * <ul>
 *   <li>TS: {@code packages/runar-compiler/src/passes/fiat-shamir-kb-codegen.ts}</li>
 *   <li>Rust: {@code compilers/rust/src/codegen/fiat_shamir_kb.rs}</li>
 *   <li>Python: {@code compilers/python/runar_compiler/codegen/fiat_shamir_kb.py}</li>
 *   <li>Zig: {@code compilers/zig/src/passes/helpers/fiat_shamir_kb_emitters.zig}</li>
 *   <li>Ruby: {@code compilers/ruby/lib/runar_compiler/codegen/fiat_shamir_kb.rb}</li>
 * </ul>
 */
public final class FiatShamirKb {

    private FiatShamirKb() {}

    /** Duplex sponge width (number of KoalaBear elements in the state). */
    public static final int FS_SPONGE_WIDTH = 16;

    /** Duplex sponge rate (absorb/squeeze chunk size in elements). */
    public static final int FS_SPONGE_RATE = 8;

    /**
     * Builtin names that route through {@link #dispatch}. The only
     * user-facing entry point is {@code verifySP1FRI}; the transcript
     * itself is driver-only.
     */
    private static final Set<String> NAMES = Set.of(
        "verifySP1FRI"
    );

    public static boolean isFiatShamirKbBuiltin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Always throws {@link UnsupportedOperationException}. See {@link BabyBear#dispatch}.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        throw new UnsupportedOperationException(
            "Java tier carries partial port only; builtin '" + funcName
                + "' belongs to the FiatShamir-KB / SP1-FRI family which is Go-only "
                + "by conformance policy — see CLAUDE.md (\"Go-only crypto codegen modules\") "
                + "and conformance/README.md (\"Per-fixture compiler allowlist\"). "
                + "Compile this contract with the Go compiler, or opt the fixture "
                + "out of the Java tier via source.json's \"compilers\" allowlist.");
    }
}
