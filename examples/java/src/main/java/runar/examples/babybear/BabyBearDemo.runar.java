package runar.examples.babybear;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.runtime.MockCrypto.bbFieldAdd;
import static runar.lang.runtime.MockCrypto.bbFieldInv;
import static runar.lang.runtime.MockCrypto.bbFieldMul;
import static runar.lang.runtime.MockCrypto.bbFieldSub;

/**
 * BabyBearDemo -- demonstrates Baby Bear prime field arithmetic.
 *
 * <p>Ports {@code examples/python/babybear/BabyBearDemo.runar.py} to
 * Java. Baby Bear is the prime field used by SP1 STARK proofs (FRI
 * verification). Field prime: {@code p = 2^31 - 2^27 + 1 = 2013265921}.
 *
 * <h2>Operations</h2>
 * <ul>
 *   <li>{@code bbFieldAdd(a, b)} -- {@code (a + b) mod p}</li>
 *   <li>{@code bbFieldSub(a, b)} -- {@code (a - b + p) mod p}</li>
 *   <li>{@code bbFieldMul(a, b)} -- {@code (a * b) mod p}</li>
 *   <li>{@code bbFieldInv(a)}    -- {@code a^(p-2) mod p} (Fermat
 *       inverse)</li>
 * </ul>
 *
 * <p><b>Note:</b> the Baby Bear builtins are part of the Go-only crypto
 * family. The Java {@link runar.lang.runtime.MockCrypto} runtime exposes
 * implementations so the contract can run inside the simulator, but the
 * Rúnar Java compiler does not yet ship Stack-IR codegen for these
 * operations -- end-to-end conformance for this fixture is exercised via
 * the Go / TS / Rust / Python / Zig / Ruby compilers.
 */
class BabyBearDemo extends SmartContract {

    BabyBearDemo() {
        super();
    }

    /** Verify field addition. */
    @Public
    void checkAdd(Bigint a, Bigint b, Bigint expected) {
        assertThat(bbFieldAdd(a.value(), b.value()).equals(expected.value()));
    }

    /** Verify field subtraction. */
    @Public
    void checkSub(Bigint a, Bigint b, Bigint expected) {
        assertThat(bbFieldSub(a.value(), b.value()).equals(expected.value()));
    }

    /** Verify field multiplication. */
    @Public
    void checkMul(Bigint a, Bigint b, Bigint expected) {
        assertThat(bbFieldMul(a.value(), b.value()).equals(expected.value()));
    }

    /** Verify field inversion: {@code a * inv(a) === 1}. */
    @Public
    void checkInv(Bigint a) {
        java.math.BigInteger inv = bbFieldInv(a.value());
        assertThat(bbFieldMul(a.value(), inv).equals(java.math.BigInteger.ONE));
    }

    /** Verify subtraction is the inverse of addition: {@code (a + b) - b === a}. */
    @Public
    void checkAddSubRoundtrip(Bigint a, Bigint b) {
        java.math.BigInteger sum = bbFieldAdd(a.value(), b.value());
        java.math.BigInteger result = bbFieldSub(sum, b.value());
        assertThat(result.equals(a.value()));
    }

    /** Verify the distributive law: {@code a * (b + c) === a*b + a*c}. */
    @Public
    void checkDistributive(Bigint a, Bigint b, Bigint c) {
        java.math.BigInteger lhs = bbFieldMul(a.value(), bbFieldAdd(b.value(), c.value()));
        java.math.BigInteger rhs = bbFieldAdd(bbFieldMul(a.value(), b.value()), bbFieldMul(a.value(), c.value()));
        assertThat(lhs.equals(rhs));
    }
}
