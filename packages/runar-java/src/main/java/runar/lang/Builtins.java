package runar.lang;

import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

/**
 * Rúnar built-in functions, as static methods for import-static use
 * inside contract source files.
 *
 * <p>Phase 1 stub: every method throws at runtime. The compiler treats
 * these as AST-level intrinsics (never executed). The off-chain
 * simulator (milestone 11) provides real implementations with mocked
 * crypto for unit testing.
 */
public final class Builtins {

    private Builtins() {}

    // Assertions ---------------------------------------------------------

    public static void assertThat(boolean condition) {
        if (!condition) {
            throw new AssertionError("Rúnar contract assertion failed");
        }
    }

    // Hashing ------------------------------------------------------------

    public static Addr hash160(PubKey pubKey) {
        throw new UnsupportedOperationException("hash160 is a compile-time intrinsic (milestone 11 off-chain simulator)");
    }

    // Signature verification --------------------------------------------

    public static boolean checkSig(Sig sig, PubKey pubKey) {
        throw new UnsupportedOperationException("checkSig is a compile-time intrinsic (milestone 11 off-chain simulator)");
    }

    // Additional builtins (sha256, ripemd160, ec*, verifyWOTS,
    // verifySLHDSA_SHA2_*, bb/kb/bn254 field arithmetic, Poseidon2,
    // Merkle roots, etc.) land in milestone 8 alongside the real
    // off-chain implementations.
}
