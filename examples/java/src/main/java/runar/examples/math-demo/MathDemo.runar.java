package runar.examples.mathdemo;

import java.math.BigInteger;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;

import static runar.lang.Builtins.abs;
import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.bool;
import static runar.lang.Builtins.clamp;
import static runar.lang.Builtins.divmod;
import static runar.lang.Builtins.gcd;
import static runar.lang.Builtins.log2;
import static runar.lang.Builtins.max;
import static runar.lang.Builtins.min;
import static runar.lang.Builtins.mulDiv;
import static runar.lang.Builtins.percentOf;
import static runar.lang.Builtins.pow;
import static runar.lang.Builtins.safediv;
import static runar.lang.Builtins.safemod;
import static runar.lang.Builtins.sign;
import static runar.lang.Builtins.sqrt;
import static runar.lang.Builtins.within;

/**
 * MathDemo -- exercises every built-in math function available in
 * Rúnar.
 *
 * <p>Bitcoin Script has limited native arithmetic (ADD, SUB, MUL, DIV,
 * MOD). Rúnar provides higher-level math functions that compile into
 * sequences of these primitives, enabling complex financial calculations
 * on-chain.
 *
 * <p>Each public method applies one math operation to the contract's
 * stored {@code value}, showing how these functions compile to pure
 * Bitcoin Script. All operations use integer math -- no floating point.
 *
 * <p>Written with raw {@link BigInteger} plus the static-imported math
 * builtins. Arithmetic is expressed via {@code BigInteger.add/subtract}
 * because Java lacks operator overloading on the class. The Rúnar parser
 * accepts both spellings.
 */
class MathDemo extends StatefulSmartContract {

    BigInteger value;

    MathDemo(BigInteger value) {
        super(value);
        this.value = value;
    }

    /** Safe division -- divides by {@code divisor}, asserting non-zero. */
    @Public
    void divideBy(BigInteger divisor) {
        this.value = safediv(this.value, divisor);
    }

    /**
     * Withdraws with a fee calculated in basis points (1 bps = 0.01%).
     * Asserts {@code amount + fee <= value}, then deducts the total.
     *
     * <p>The {@code .compareTo(...) <= 0} spelling is the Java way to
     * check BigInteger ordering. The Rúnar parser lowers it to the same
     * AST as writing {@code total <= this.value} would in TypeScript;
     * the final Bitcoin Script is identical.
     */
    @Public
    void withdrawWithFee(BigInteger amount, BigInteger feeBps) {
        BigInteger fee = percentOf(amount, feeBps);
        BigInteger total = amount.add(fee);
        assertThat(total.compareTo(this.value) <= 0);
        this.value = this.value.subtract(total);
    }

    /** Constrains the stored value to the range {@code [lo, hi]}. */
    @Public
    void clampValue(BigInteger lo, BigInteger hi) {
        this.value = clamp(this.value, lo, hi);
    }

    /** Replaces the stored value with its sign: -1, 0, or 1. */
    @Public
    void normalize() {
        this.value = sign(this.value);
    }

    /** Raises the stored value to the power {@code exp}. */
    @Public
    void exponentiate(BigInteger exp) {
        this.value = pow(this.value, exp);
    }

    /** Replaces the stored value with its integer square root. */
    @Public
    void squareRoot() {
        this.value = sqrt(this.value);
    }

    /** Replaces the stored value with {@code gcd(value, other)}. */
    @Public
    void reduceGcd(BigInteger other) {
        this.value = gcd(this.value, other);
    }

    /**
     * Computes {@code (value * numerator) / denominator} with intermediate
     * precision to avoid overflow. Replaces the stored value.
     */
    @Public
    void scaleByRatio(BigInteger numerator, BigInteger denominator) {
        this.value = mulDiv(this.value, numerator, denominator);
    }

    /** Replaces the stored value with {@code floor(log2(value))}. */
    @Public
    void computeLog2() {
        this.value = log2(this.value);
    }

    /** Replaces the stored value with its absolute value. */
    @Public
    void makeAbs() {
        this.value = abs(this.value);
    }

    /** Replaces the stored value with {@code min(value, other)}. */
    @Public
    void takeMin(BigInteger other) {
        this.value = min(this.value, other);
    }

    /** Replaces the stored value with {@code max(value, other)}. */
    @Public
    void takeMax(BigInteger other) {
        this.value = max(this.value, other);
    }

    /**
     * Asserts that the stored value lies in the half-open range
     * {@code [lo, hi)} -- the semantics of Bitcoin Script's OP_WITHIN.
     */
    @Public
    void assertWithin(BigInteger lo, BigInteger hi) {
        assertThat(within(this.value, lo, hi));
    }

    /**
     * Safe modulo -- replaces the stored value with
     * {@code value mod divisor}, asserting that {@code divisor} is non-zero.
     */
    @Public
    void moduloBy(BigInteger divisor) {
        this.value = safemod(this.value, divisor);
    }

    /**
     * Replaces the stored value with {@code value / divisor} via Rúnar's
     * {@code divmod} builtin (canonical OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD
     * OP_DROP sequence).
     */
    @Public
    void divmodBy(BigInteger divisor) {
        this.value = divmod(this.value, divisor);
    }

    /**
     * Asserts that the stored value is "truthy" (non-zero) using the
     * dedicated {@code bool} builtin which compiles to OP_0NOTEQUAL.
     */
    @Public
    void assertNonZero() {
        assertThat(bool(this.value));
    }
}
