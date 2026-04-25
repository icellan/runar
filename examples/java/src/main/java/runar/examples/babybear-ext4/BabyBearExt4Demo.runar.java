package runar.examples.babybearext4;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.runtime.MockCrypto.bbFieldAdd;
import static runar.lang.runtime.MockCrypto.bbFieldInv;
import static runar.lang.runtime.MockCrypto.bbFieldMul;
import static runar.lang.runtime.MockCrypto.bbFieldSub;

/**
 * BabyBearExt4Demo -- demonstrates Baby Bear Ext4 (quartic extension
 * field) arithmetic and the core FRI colinearity folding relation used in
 * SP1 STARK proofs.
 *
 * <p>Ports {@code examples/python/babybear-ext4/BabyBearExt4Demo.runar.py}
 * to Java.
 *
 * <p><b>Note:</b> the Baby Bear Ext4 builtins ({@code bbExt4Mul0..3},
 * {@code bbExt4Inv0..3}) are part of the Go-only crypto family. They are
 * not yet exposed by the Rúnar Java SDK ({@link runar.lang.Builtins}) nor
 * by {@link runar.lang.runtime.MockCrypto}, so this contract declares
 * package-private stubs that throw at runtime. The Rúnar Java compiler
 * also does not yet ship Stack-IR codegen for these operations -- end-to-
 * end conformance for this fixture is exercised via the Go / TS / Rust /
 * Python / Zig / Ruby compilers.
 */
class BabyBearExt4Demo extends SmartContract {

    BabyBearExt4Demo() {
        super();
    }

    /** Ext4 multiplication: verify all 4 components. */
    @Public
    void checkMul(
        Bigint a0, Bigint a1, Bigint a2, Bigint a3,
        Bigint b0, Bigint b1, Bigint b2, Bigint b3,
        Bigint e0, Bigint e1, Bigint e2, Bigint e3
    ) {
        assertThat(bbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3).eq(e0));
        assertThat(bbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3).eq(e1));
        assertThat(bbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3).eq(e2));
        assertThat(bbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3).eq(e3));
    }

    /** Ext4 inverse: verify all 4 components. */
    @Public
    void checkInv(
        Bigint a0, Bigint a1, Bigint a2, Bigint a3,
        Bigint e0, Bigint e1, Bigint e2, Bigint e3
    ) {
        assertThat(bbExt4Inv0(a0, a1, a2, a3).eq(e0));
        assertThat(bbExt4Inv1(a0, a1, a2, a3).eq(e1));
        assertThat(bbExt4Inv2(a0, a1, a2, a3).eq(e2));
        assertThat(bbExt4Inv3(a0, a1, a2, a3).eq(e3));
    }

    /** FRI colinearity check: the core FRI folding relation. */
    @Public
    void checkFriFold(
        Bigint x,
        Bigint fx0, Bigint fx1, Bigint fx2, Bigint fx3,
        Bigint fnx0, Bigint fnx1, Bigint fnx2, Bigint fnx3,
        Bigint a0, Bigint a1, Bigint a2, Bigint a3,
        Bigint eg0, Bigint eg1, Bigint eg2, Bigint eg3
    ) {
        BigInteger s0 = bbFieldAdd(fx0.value(), fnx0.value());
        BigInteger s1 = bbFieldAdd(fx1.value(), fnx1.value());
        BigInteger s2 = bbFieldAdd(fx2.value(), fnx2.value());
        BigInteger s3 = bbFieldAdd(fx3.value(), fnx3.value());
        BigInteger inv2 = bbFieldInv(BigInteger.TWO);
        BigInteger hs0 = bbFieldMul(s0, inv2);
        BigInteger hs1 = bbFieldMul(s1, inv2);
        BigInteger hs2 = bbFieldMul(s2, inv2);
        BigInteger hs3 = bbFieldMul(s3, inv2);
        Bigint d0 = new Bigint(bbFieldSub(fx0.value(), fnx0.value()));
        Bigint d1 = new Bigint(bbFieldSub(fx1.value(), fnx1.value()));
        Bigint d2 = new Bigint(bbFieldSub(fx2.value(), fnx2.value()));
        Bigint d3 = new Bigint(bbFieldSub(fx3.value(), fnx3.value()));
        Bigint ad0 = bbExt4Mul0(a0, a1, a2, a3, d0, d1, d2, d3);
        Bigint ad1 = bbExt4Mul1(a0, a1, a2, a3, d0, d1, d2, d3);
        Bigint ad2 = bbExt4Mul2(a0, a1, a2, a3, d0, d1, d2, d3);
        Bigint ad3 = bbExt4Mul3(a0, a1, a2, a3, d0, d1, d2, d3);
        BigInteger inv2x = bbFieldInv(bbFieldMul(BigInteger.TWO, x.value()));
        BigInteger at0 = bbFieldMul(ad0.value(), inv2x);
        BigInteger at1 = bbFieldMul(ad1.value(), inv2x);
        BigInteger at2 = bbFieldMul(ad2.value(), inv2x);
        BigInteger at3 = bbFieldMul(ad3.value(), inv2x);
        BigInteger g0 = bbFieldAdd(hs0, at0);
        BigInteger g1 = bbFieldAdd(hs1, at1);
        BigInteger g2 = bbFieldAdd(hs2, at2);
        BigInteger g3 = bbFieldAdd(hs3, at3);
        assertThat(g0.equals(eg0.value()));
        assertThat(g1.equals(eg1.value()));
        assertThat(g2.equals(eg2.value()));
        assertThat(g3.equals(eg3.value()));
    }

    // ------------------------------------------------------------------
    // Stubs for the Ext4 builtins that the Rúnar Java SDK does not yet
    // expose. The Rúnar compiler intercepts these calls at parse time
    // (the Java parser recognises the names as Go-only intrinsics), so
    // these bodies are never reached in compiled Bitcoin Script. They
    // throw at JVM runtime to signal that the simulator path is not
    // wired for the Ext4 family yet.
    // ------------------------------------------------------------------

    private static Bigint bbExt4Mul0(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                     Bigint b0, Bigint b1, Bigint b2, Bigint b3) {
        throw new UnsupportedOperationException("bbExt4Mul0 is a Go-only Rúnar builtin (no Java SDK runtime yet)");
    }

    private static Bigint bbExt4Mul1(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                     Bigint b0, Bigint b1, Bigint b2, Bigint b3) {
        throw new UnsupportedOperationException("bbExt4Mul1 is a Go-only Rúnar builtin (no Java SDK runtime yet)");
    }

    private static Bigint bbExt4Mul2(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                     Bigint b0, Bigint b1, Bigint b2, Bigint b3) {
        throw new UnsupportedOperationException("bbExt4Mul2 is a Go-only Rúnar builtin (no Java SDK runtime yet)");
    }

    private static Bigint bbExt4Mul3(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                     Bigint b0, Bigint b1, Bigint b2, Bigint b3) {
        throw new UnsupportedOperationException("bbExt4Mul3 is a Go-only Rúnar builtin (no Java SDK runtime yet)");
    }

    private static Bigint bbExt4Inv0(Bigint a0, Bigint a1, Bigint a2, Bigint a3) {
        throw new UnsupportedOperationException("bbExt4Inv0 is a Go-only Rúnar builtin (no Java SDK runtime yet)");
    }

    private static Bigint bbExt4Inv1(Bigint a0, Bigint a1, Bigint a2, Bigint a3) {
        throw new UnsupportedOperationException("bbExt4Inv1 is a Go-only Rúnar builtin (no Java SDK runtime yet)");
    }

    private static Bigint bbExt4Inv2(Bigint a0, Bigint a1, Bigint a2, Bigint a3) {
        throw new UnsupportedOperationException("bbExt4Inv2 is a Go-only Rúnar builtin (no Java SDK runtime yet)");
    }

    private static Bigint bbExt4Inv3(Bigint a0, Bigint a1, Bigint a2, Bigint a3) {
        throw new UnsupportedOperationException("bbExt4Inv3 is a Go-only Rúnar builtin (no Java SDK runtime yet)");
    }
}
