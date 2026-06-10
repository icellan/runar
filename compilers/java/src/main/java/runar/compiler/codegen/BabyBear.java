package runar.compiler.codegen;

import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.StackOp;

/**
 * BabyBear field arithmetic codegen — <b>Java tier stub, intentionally
 * non-functional</b>.
 *
 * <p>BabyBear / KoalaBear / Poseidon2 / BN254 / Groth16 / SP1 FRI /
 * FiatShamir-KB / sha256-Merkle are <b>Go-only conformance targets</b>
 * by project policy (see {@code CLAUDE.md} ⇒ "Go-only crypto codegen
 * modules"). They power Mode-3 STARK / FRI verification flows that the
 * project has explicitly scoped to the Go reference compiler.
 *
 * <p>The other five non-Go tiers (TypeScript, Rust, Python, Zig, Ruby)
 * carry partial ports of these modules for historical reasons. This
 * stub exists for <b>module-presence parity</b> only — every builtin
 * name in this family routes through {@link #dispatch} which always
 * throws {@link UnsupportedOperationException}. Fixtures that exercise
 * these primitives carry an explicit {@code "compilers": ["go"]}
 * allowlist in {@code source.json}; the Java compiler still parses all
 * nine source formats for those fixtures via the all-tier parser-only
 * matrix.
 *
 * <p>Reference implementations (for any future port):
 * <ul>
 *   <li>TS: {@code packages/runar-compiler/src/passes/babybear-codegen.ts}</li>
 *   <li>Rust: {@code compilers/rust/src/codegen/babybear.rs}</li>
 *   <li>Python: {@code compilers/python/runar_compiler/codegen/babybear.py}</li>
 *   <li>Zig: {@code compilers/zig/src/passes/helpers/babybear_emitters.zig}</li>
 *   <li>Ruby: {@code compilers/ruby/lib/runar_compiler/codegen/babybear.rb}</li>
 * </ul>
 *
 * <p>The constants below are the public BabyBear field parameters used
 * by SP1 STARK proofs.
 */
public final class BabyBear {

    private BabyBear() {}

    /** BabyBear field prime {@code p = 2^31 - 2^27 + 1 = 2013265921}. */
    public static final long BB_P = 2013265921L;

    /** {@code p - 2}, used for Fermat's little theorem modular inverse. */
    public static final long BB_P_MINUS_2 = BB_P - 2L;

    /** Quartic extension irreducible polynomial coefficient {@code W = 11}. */
    public static final long BB_W = 11L;

    /** Builtin names that route through {@link #dispatch}. */
    private static final Set<String> NAMES = Set.of(
        // Base-field arithmetic
        "bbFieldAdd", "bbFieldSub", "bbFieldMul", "bbFieldInv",
        // Quartic extension multiplication (per-limb)
        "bbExt4Mul0", "bbExt4Mul1", "bbExt4Mul2", "bbExt4Mul3",
        // Quartic extension inverse (per-limb)
        "bbExt4Inv0", "bbExt4Inv1", "bbExt4Inv2", "bbExt4Inv3"
    );

    public static boolean isBabyBearBuiltin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Always throws {@link UnsupportedOperationException}. The Java tier
     * carries a presence-only stub of this module; actual emission is
     * Go-only by project policy.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        throw new UnsupportedOperationException(
            "Java tier carries partial port only; builtin '" + funcName
                + "' belongs to the BabyBear family which is Go-only by conformance "
                + "policy — see CLAUDE.md (\"Go-only crypto codegen modules\") and "
                + "conformance/README.md (\"Per-fixture compiler allowlist\"). "
                + "Compile this contract with the Go compiler, or opt the fixture "
                + "out of the Java tier via source.json's \"compilers\" allowlist.");
    }
}
