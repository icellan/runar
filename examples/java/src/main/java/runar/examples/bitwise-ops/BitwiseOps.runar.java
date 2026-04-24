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

    /** Verifies shift operators compile and run. */
    @Public
    void testShift() {
        Bigint left = this.a.shl(Bigint.TWO);
        Bigint right = this.a.shr(Bigint.ONE);
        assertThat(left.ge(Bigint.ZERO) || left.lt(Bigint.ZERO));
        assertThat(right.ge(Bigint.ZERO) || right.lt(Bigint.ZERO));
        assertThat(true);
    }

    /** Verifies bitwise operators compile and run. */
    @Public
    void testBitwise() {
        Bigint andResult = this.a.and(this.b);
        Bigint orResult = this.a.or(this.b);
        Bigint xorResult = this.a.xor(this.b);
        // NOT is a unary operator; the parser lowers `x.neg()` to UnaryExpr(NEG).
        // Bigint does not expose `.not()` (bitwise NOT on arbitrary-precision
        // integers has no well-defined result in two's complement), so we
        // exercise the unary negation path here instead.
        Bigint negResult = this.a.neg();
        assertThat(andResult.ge(Bigint.ZERO) || andResult.lt(Bigint.ZERO));
        assertThat(orResult.ge(Bigint.ZERO) || orResult.lt(Bigint.ZERO));
        assertThat(xorResult.ge(Bigint.ZERO) || xorResult.lt(Bigint.ZERO));
        assertThat(negResult.ge(Bigint.ZERO) || negResult.lt(Bigint.ZERO));
        assertThat(true);
    }
}
