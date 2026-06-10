package runar.compiler.codegen;

import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.StackOp;

/**
 * KoalaBear field arithmetic codegen — <b>Java tier stub, intentionally
 * non-functional</b>.
 *
 * <p>See {@link BabyBear} for the project-policy rationale: KoalaBear is
 * part of the Go-only Mode-3 STARK / FRI verifier family. This module
 * exists for module-presence parity with the other five non-Go tiers.
 *
 * <p>Reference implementations:
 * <ul>
 *   <li>TS: {@code packages/runar-compiler/src/passes/koalabear-codegen.ts}</li>
 *   <li>Rust: {@code compilers/rust/src/codegen/koalabear.rs}</li>
 *   <li>Python: {@code compilers/python/runar_compiler/codegen/koalabear.py}</li>
 *   <li>Zig: {@code compilers/zig/src/passes/helpers/koalabear_emitters.zig}</li>
 *   <li>Ruby: {@code compilers/ruby/lib/runar_compiler/codegen/koalabear.rb}</li>
 * </ul>
 */
public final class KoalaBear {

    private KoalaBear() {}

    /** KoalaBear field prime {@code p = 2^31 - 2^24 + 1 = 2130706433}. */
    public static final long KB_P = 2130706433L;

    /** {@code p - 2}, for Fermat's little theorem modular inverse. */
    public static final long KB_P_MINUS_2 = 2130706431L;

    /** Quartic extension irreducible polynomial coefficient {@code W = 3}. */
    public static final long KB_W = 3L;

    /** Builtin names that route through {@link #dispatch}. */
    private static final Set<String> NAMES = Set.of(
        // Base-field arithmetic
        "kbFieldAdd", "kbFieldSub", "kbFieldMul", "kbFieldInv",
        // Quartic extension multiplication (per-limb)
        "kbExt4Mul0", "kbExt4Mul1", "kbExt4Mul2", "kbExt4Mul3",
        // Quartic extension inverse (per-limb)
        "kbExt4Inv0", "kbExt4Inv1", "kbExt4Inv2", "kbExt4Inv3"
    );

    public static boolean isKoalaBearBuiltin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Always throws {@link UnsupportedOperationException}. See {@link BabyBear#dispatch}.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        throw new UnsupportedOperationException(
            "Java tier carries partial port only; builtin '" + funcName
                + "' belongs to the KoalaBear family which is Go-only by conformance "
                + "policy — see CLAUDE.md (\"Go-only crypto codegen modules\") and "
                + "conformance/README.md (\"Per-fixture compiler allowlist\"). "
                + "Compile this contract with the Go compiler, or opt the fixture "
                + "out of the Java tier via source.json's \"compilers\" allowlist.");
    }
}
