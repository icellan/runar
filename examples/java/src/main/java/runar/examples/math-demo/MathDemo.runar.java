package runar.examples.mathdemo;

import java.math.BigInteger;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.clamp;
import static runar.lang.Builtins.gcd;
import static runar.lang.Builtins.log2;
import static runar.lang.Builtins.mulDiv;
import static runar.lang.Builtins.percentOf;
import static runar.lang.Builtins.pow;
import static runar.lang.Builtins.safediv;
import static runar.lang.Builtins.sign;
import static runar.lang.Builtins.sqrt;

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
}
