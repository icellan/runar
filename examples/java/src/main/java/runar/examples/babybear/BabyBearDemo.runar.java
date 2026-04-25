package runar.examples.babybear;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.bbFieldAdd;
import static runar.lang.Builtins.bbFieldInv;
import static runar.lang.Builtins.bbFieldMul;
import static runar.lang.Builtins.bbFieldSub;

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
 * <p>This contract is Rúnar-pure source: every value flows as a
 * {@link Bigint} through {@link runar.lang.Builtins} shims, so the
 * Rúnar Java frontend (parse → validate → typecheck) accepts it as a
 * round-trip {@link runar.lang.sdk.CompileCheck} fixture. The Baby Bear
 * builtins are part of the Go-only crypto family — the Rúnar Java
 * compiler does not yet ship Stack-IR codegen for them, so end-to-end
 * conformance for this fixture is exercised via the Go / TS / Rust /
 * Python / Zig / Ruby compilers.
 */
class BabyBearDemo extends SmartContract {

    BabyBearDemo() {
        super();
    }

    /** Verify field addition. */
    @Public
    void checkAdd(Bigint a, Bigint b, Bigint expected) {
        assertThat(bbFieldAdd(a, b).eq(expected));
    }

    /** Verify field subtraction. */
    @Public
    void checkSub(Bigint a, Bigint b, Bigint expected) {
        assertThat(bbFieldSub(a, b).eq(expected));
    }

    /** Verify field multiplication. */
    @Public
    void checkMul(Bigint a, Bigint b, Bigint expected) {
        assertThat(bbFieldMul(a, b).eq(expected));
    }

    /** Verify field inversion: {@code a * inv(a) === 1}. */
    @Public
    void checkInv(Bigint a) {
        Bigint inv = bbFieldInv(a);
        assertThat(bbFieldMul(a, inv).eq(Bigint.ONE));
    }

    /** Verify subtraction is the inverse of addition: {@code (a + b) - b === a}. */
    @Public
    void checkAddSubRoundtrip(Bigint a, Bigint b) {
        Bigint sum = bbFieldAdd(a, b);
        Bigint result = bbFieldSub(sum, b);
        assertThat(result.eq(a));
    }

    /** Verify the distributive law: {@code a * (b + c) === a*b + a*c}. */
    @Public
    void checkDistributive(Bigint a, Bigint b, Bigint c) {
        Bigint lhs = bbFieldMul(a, bbFieldAdd(b, c));
        Bigint rhs = bbFieldAdd(bbFieldMul(a, b), bbFieldMul(a, c));
        assertThat(lhs.eq(rhs));
    }
}
