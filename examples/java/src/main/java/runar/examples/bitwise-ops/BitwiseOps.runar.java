package runar.examples.bitwiseops;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * BitwiseOps -- exercises every bitwise / shift operator on Bigint
 * values. Uses the {@link Bigint} wrapper's method form so Java accepts
 * the source natively; the parser lowers {@code .shl}, {@code .shr},
 * {@code .and}, {@code .or}, {@code .xor}, and unary negation into the
 * canonical {@code BinaryExpr} / {@code UnaryExpr} AST nodes that other
 * Rúnar frontends produce from {@code <<}, {@code >>}, {@code &},
 * {@code |}, {@code ^}, and {@code ~}.
 *
 * <p>Mirrors {@code examples/go/bitwise-ops/BitwiseOps.runar.go}.
 */
class BitwiseOps extends SmartContract {

    @Readonly Bigint a;
    @Readonly Bigint b;

    BitwiseOps(Bigint a, Bigint b) {
        super(a, b);
        this.a = a;
        this.b = b;
    }

    /** Checks the caller-supplied shift results. */
    @Public
    void testShift(Bigint expectedLeft, Bigint expectedRight) {
        Bigint left = this.a.shl(Bigint.TWO);
        Bigint right = this.a.shr(Bigint.ONE);
        assertThat(left.eq(expectedLeft));
        assertThat(right.eq(expectedRight));
    }

    /**
     * Checks the caller-supplied AND/OR/XOR results; NOT is checked by double
     * inversion and De Morgan's law (see the TS source for why).
     */
    @Public
    void testBitwise(Bigint expectedAnd, Bigint expectedOr, Bigint expectedXor) {
        Bigint andResult = this.a.and(this.b);
        Bigint orResult = this.a.or(this.b);
        Bigint xorResult = this.a.xor(this.b);
        // Bitwise NOT (~). Mirrors java.math.BigInteger#not(); the Bigint
        // wrapper exposes the same method, and every frontend lowers
        // `x.not()` to UnaryExpr(BIT_NOT, x), matching the canonical TS
        // contract's `~this.a`.
        Bigint notResult = this.a.not();
        assertThat(andResult.eq(expectedAnd));
        assertThat(orResult.eq(expectedOr));
        assertThat(xorResult.eq(expectedXor));
        assertThat(notResult.not().eq(this.a));
        assertThat(this.a.or(this.b).not().eq(notResult.and(this.b.not())));
    }
}
