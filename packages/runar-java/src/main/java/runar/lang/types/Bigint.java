package runar.lang.types;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Convenience wrapper around {@link BigInteger} exposing Rúnar-named
 * methods so contract bodies written in Java can express arithmetic
 * without spelling out {@code add}/{@code subtract}/{@code multiply}
 * every time. The Rúnar Java parser recognises these method calls and
 * lowers them to the canonical arithmetic AST ({@code BinaryExpr} /
 * {@code UnaryExpr}), so the compiled Bitcoin Script is byte-identical
 * to what you would get from the {@code BigInteger.add}/{@code subtract}
 * spelling or from writing {@code a + b} on raw {@code BigInteger}
 * operands.
 *
 * <p>Instances are immutable; every method returns a new {@code Bigint}.
 * Equality matches the wrapped {@link BigInteger}.
 *
 * <h2>Method catalogue</h2>
 * <table>
 *   <caption>Bigint methods recognised by the parser</caption>
 *   <tr><th>method</th><th>AST lowering</th></tr>
 *   <tr><td>{@code plus(b)}</td>   <td>{@code BinaryExpr(ADD, a, b)}</td></tr>
 *   <tr><td>{@code minus(b)}</td>  <td>{@code BinaryExpr(SUB, a, b)}</td></tr>
 *   <tr><td>{@code times(b)}</td>  <td>{@code BinaryExpr(MUL, a, b)}</td></tr>
 *   <tr><td>{@code div(b)}</td>    <td>{@code BinaryExpr(DIV, a, b)}</td></tr>
 *   <tr><td>{@code mod(b)}</td>    <td>{@code BinaryExpr(MOD, a, b)}</td></tr>
 *   <tr><td>{@code shl(b)}</td>    <td>{@code BinaryExpr(SHL, a, b)}</td></tr>
 *   <tr><td>{@code shr(b)}</td>    <td>{@code BinaryExpr(SHR, a, b)}</td></tr>
 *   <tr><td>{@code and(b)}</td>    <td>{@code BinaryExpr(BIT_AND, a, b)}</td></tr>
 *   <tr><td>{@code or(b)}</td>     <td>{@code BinaryExpr(BIT_OR, a, b)}</td></tr>
 *   <tr><td>{@code xor(b)}</td>    <td>{@code BinaryExpr(BIT_XOR, a, b)}</td></tr>
 *   <tr><td>{@code gt(b)}</td>     <td>{@code BinaryExpr(GT, a, b)}</td></tr>
 *   <tr><td>{@code lt(b)}</td>     <td>{@code BinaryExpr(LT, a, b)}</td></tr>
 *   <tr><td>{@code ge(b)}</td>     <td>{@code BinaryExpr(GE, a, b)}</td></tr>
 *   <tr><td>{@code le(b)}</td>     <td>{@code BinaryExpr(LE, a, b)}</td></tr>
 *   <tr><td>{@code eq(b)}</td>     <td>{@code BinaryExpr(EQ, a, b)}</td></tr>
 *   <tr><td>{@code neq(b)}</td>    <td>{@code BinaryExpr(NEQ, a, b)}</td></tr>
 *   <tr><td>{@code neg()}</td>     <td>{@code UnaryExpr(NEG, a)}</td></tr>
 *   <tr><td>{@code abs()}</td>     <td>{@code CallExpr(abs, a)}</td></tr>
 * </table>
 */
public final class Bigint {

    public static final Bigint ZERO = new Bigint(BigInteger.ZERO);
    public static final Bigint ONE = new Bigint(BigInteger.ONE);
    public static final Bigint TWO = new Bigint(BigInteger.TWO);
    public static final Bigint TEN = new Bigint(BigInteger.TEN);

    private final BigInteger value;

    public Bigint(BigInteger value) {
        this.value = Objects.requireNonNull(value, "value");
    }

    public Bigint(long value) {
        this(BigInteger.valueOf(value));
    }

    public static Bigint of(long v) {
        return new Bigint(BigInteger.valueOf(v));
    }

    public static Bigint of(BigInteger v) {
        return new Bigint(v);
    }

    public BigInteger value() {
        return value;
    }

    // -----------------------------------------------------------------
    // Arithmetic — recognised by the Rúnar Java parser and lowered to
    // BinaryExpr / UnaryExpr during AST conversion.
    // -----------------------------------------------------------------

    public Bigint plus(Bigint other)  { return new Bigint(value.add(other.value)); }
    public Bigint minus(Bigint other) { return new Bigint(value.subtract(other.value)); }
    public Bigint times(Bigint other) { return new Bigint(value.multiply(other.value)); }
    public Bigint div(Bigint other)   { return new Bigint(value.divide(other.value)); }
    public Bigint mod(Bigint other)   { return new Bigint(value.mod(other.value.abs())); }

    public Bigint shl(Bigint other) { return new Bigint(value.shiftLeft(other.value.intValueExact())); }
    public Bigint shr(Bigint other) { return new Bigint(value.shiftRight(other.value.intValueExact())); }

    public Bigint and(Bigint other) { return new Bigint(value.and(other.value)); }
    public Bigint or(Bigint other)  { return new Bigint(value.or(other.value)); }
    public Bigint xor(Bigint other) { return new Bigint(value.xor(other.value)); }

    public boolean gt(Bigint other)  { return value.compareTo(other.value) >  0; }
    public boolean lt(Bigint other)  { return value.compareTo(other.value) <  0; }
    public boolean ge(Bigint other)  { return value.compareTo(other.value) >= 0; }
    public boolean le(Bigint other)  { return value.compareTo(other.value) <= 0; }
    public boolean eq(Bigint other)  { return value.equals(other.value); }
    public boolean neq(Bigint other) { return !value.equals(other.value); }

    public Bigint neg() { return new Bigint(value.negate()); }
    public Bigint abs() { return new Bigint(value.abs()); }

    // -----------------------------------------------------------------
    // Value semantics
    // -----------------------------------------------------------------

    @Override
    public boolean equals(Object o) {
        return o instanceof Bigint that && this.value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
