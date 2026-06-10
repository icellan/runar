package runar.compiler.codegen;

import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.StackOp;

/**
 * BN254 (alt-bn128) field, G1 curve, pairing, and Groth16
 * witness-assisted verifier codegen — <b>Java tier stub, intentionally
 * non-functional</b>.
 *
 * <p>See {@link BabyBear} for the project-policy rationale. BN254 +
 * Groth16 power the EVM-compatible SNARK verifier flow that the project
 * has explicitly scoped to the Go reference compiler. This module is
 * kept for module-presence parity with the other five non-Go tiers.
 *
 * <p>Reference implementations:
 * <ul>
 *   <li>TS: {@code packages/runar-compiler/src/passes/bn254-codegen.ts}</li>
 *   <li>Rust: {@code compilers/rust/src/codegen/bn254.rs}</li>
 *   <li>Python: {@code compilers/python/runar_compiler/codegen/bn254.py}</li>
 *   <li>Zig: {@code compilers/zig/src/passes/helpers/bn254_emitters.zig}</li>
 *   <li>Ruby: {@code compilers/ruby/lib/runar_compiler/codegen/bn254.rb}</li>
 * </ul>
 */
public final class Bn254 {

    private Bn254() {}

    /**
     * BN254 field prime
     * {@code p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47}
     * in big-endian bytes.
     */
    public static final byte[] BN254_FIELD_P_BE = new byte[] {
        (byte) 0x30, (byte) 0x64, (byte) 0x4e, (byte) 0x72,
        (byte) 0xe1, (byte) 0x31, (byte) 0xa0, (byte) 0x29,
        (byte) 0xb8, (byte) 0x50, (byte) 0x45, (byte) 0xb6,
        (byte) 0x81, (byte) 0x81, (byte) 0x58, (byte) 0x5d,
        (byte) 0x97, (byte) 0x81, (byte) 0x6a, (byte) 0x91,
        (byte) 0x68, (byte) 0x71, (byte) 0xca, (byte) 0x8d,
        (byte) 0x3c, (byte) 0x20, (byte) 0x8c, (byte) 0x16,
        (byte) 0xd8, (byte) 0x7c, (byte) 0xfd, (byte) 0x47,
    };

    /**
     * BN254 curve order
     * {@code r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001}
     * in big-endian bytes.
     */
    public static final byte[] BN254_CURVE_R_BE = new byte[] {
        (byte) 0x30, (byte) 0x64, (byte) 0x4e, (byte) 0x72,
        (byte) 0xe1, (byte) 0x31, (byte) 0xa0, (byte) 0x29,
        (byte) 0xb8, (byte) 0x50, (byte) 0x45, (byte) 0xb6,
        (byte) 0x81, (byte) 0x81, (byte) 0x58, (byte) 0x5d,
        (byte) 0x28, (byte) 0x33, (byte) 0xe8, (byte) 0x48,
        (byte) 0x79, (byte) 0xb9, (byte) 0x70, (byte) 0x91,
        (byte) 0x43, (byte) 0xe1, (byte) 0xf5, (byte) 0x93,
        (byte) 0xf0, (byte) 0x00, (byte) 0x00, (byte) 0x01,
    };

    /** Builtin names that route through {@link #dispatch}. */
    private static final Set<String> NAMES = Set.of(
        // Base-field arithmetic
        "bn254FieldAdd", "bn254FieldSub", "bn254FieldMul",
        "bn254FieldInv", "bn254FieldNeg",
        // G1 curve operations
        "bn254G1Add", "bn254G1ScalarMul", "bn254G1Negate", "bn254G1OnCurve",
        // Pairing and Groth16 verifier helpers
        "bn254Pairing", "bn254MultiPairing3", "bn254MultiPairing4",
        "assertGroth16WitnessAssisted",
        "assertGroth16WitnessAssistedWithMSM",
        "groth16PublicInput"
    );

    public static boolean isBn254Builtin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Always throws {@link UnsupportedOperationException}. See {@link BabyBear#dispatch}.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        throw new UnsupportedOperationException(
            "Java tier carries partial port only; builtin '" + funcName
                + "' belongs to the BN254/Groth16 family which is Go-only by "
                + "conformance policy — see CLAUDE.md (\"Go-only crypto codegen modules\") "
                + "and conformance/README.md (\"Per-fixture compiler allowlist\"). "
                + "Compile this contract with the Go compiler, or opt the fixture "
                + "out of the Java tier via source.json's \"compilers\" allowlist.");
    }
}
