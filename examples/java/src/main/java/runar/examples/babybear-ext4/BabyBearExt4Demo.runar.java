package runar.examples.babybearext4;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.bbExt4Inv0;
import static runar.lang.Builtins.bbExt4Inv1;
import static runar.lang.Builtins.bbExt4Inv2;
import static runar.lang.Builtins.bbExt4Inv3;
import static runar.lang.Builtins.bbExt4Mul0;
import static runar.lang.Builtins.bbExt4Mul1;
import static runar.lang.Builtins.bbExt4Mul2;
import static runar.lang.Builtins.bbExt4Mul3;
import static runar.lang.Builtins.bbFieldAdd;
import static runar.lang.Builtins.bbFieldInv;
import static runar.lang.Builtins.bbFieldMul;
import static runar.lang.Builtins.bbFieldSub;

/**
 * BabyBearExt4Demo -- demonstrates Baby Bear Ext4 (quartic extension
 * field) arithmetic and the core FRI colinearity folding relation used in
 * SP1 STARK proofs.
 *
 * <p>Ports {@code examples/python/babybear-ext4/BabyBearExt4Demo.runar.py}
 * to Java.
 *
 * <p>This contract is Rúnar-pure source: all arithmetic flows as
 * {@link Bigint} values through {@link runar.lang.Builtins} shims, so the
 * Rúnar Java frontend (parse → validate → typecheck) accepts it as a
 * round-trip {@link runar.lang.sdk.CompileCheck} fixture.
 *
 * <p><b>Note:</b> the Baby Bear Ext4 builtins ({@code bbExt4Mul0..3},
 * {@code bbExt4Inv0..3}) are part of the Go-only crypto family. The Java
 * SDK exposes them through {@link runar.lang.Builtins} for source-level
 * compatibility but {@link runar.lang.runtime.MockCrypto} does not yet
 * ship runtime implementations — calling them from the simulator throws.
 * The Rúnar Java compiler also does not yet ship Stack-IR codegen for
 * these operations; end-to-end conformance for this fixture is exercised
 * via the Go / TS / Rust / Python / Zig / Ruby compilers.
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
        Bigint s0 = bbFieldAdd(fx0, fnx0);
        Bigint s1 = bbFieldAdd(fx1, fnx1);
        Bigint s2 = bbFieldAdd(fx2, fnx2);
        Bigint s3 = bbFieldAdd(fx3, fnx3);
        Bigint inv2 = bbFieldInv(Bigint.TWO);
        Bigint hs0 = bbFieldMul(s0, inv2);
        Bigint hs1 = bbFieldMul(s1, inv2);
        Bigint hs2 = bbFieldMul(s2, inv2);
        Bigint hs3 = bbFieldMul(s3, inv2);
        Bigint d0 = bbFieldSub(fx0, fnx0);
        Bigint d1 = bbFieldSub(fx1, fnx1);
        Bigint d2 = bbFieldSub(fx2, fnx2);
        Bigint d3 = bbFieldSub(fx3, fnx3);
        Bigint ad0 = bbExt4Mul0(a0, a1, a2, a3, d0, d1, d2, d3);
        Bigint ad1 = bbExt4Mul1(a0, a1, a2, a3, d0, d1, d2, d3);
        Bigint ad2 = bbExt4Mul2(a0, a1, a2, a3, d0, d1, d2, d3);
        Bigint ad3 = bbExt4Mul3(a0, a1, a2, a3, d0, d1, d2, d3);
        Bigint inv2x = bbFieldInv(bbFieldMul(Bigint.TWO, x));
        Bigint at0 = bbFieldMul(ad0, inv2x);
        Bigint at1 = bbFieldMul(ad1, inv2x);
        Bigint at2 = bbFieldMul(ad2, inv2x);
        Bigint at3 = bbFieldMul(ad3, inv2x);
        Bigint g0 = bbFieldAdd(hs0, at0);
        Bigint g1 = bbFieldAdd(hs1, at1);
        Bigint g2 = bbFieldAdd(hs2, at2);
        Bigint g3 = bbFieldAdd(hs3, at3);
        assertThat(g0.eq(eg0));
        assertThat(g1.eq(eg1));
        assertThat(g2.eq(eg2));
        assertThat(g3.eq(eg3));
    }
}
