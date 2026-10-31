package runar.compiler.ir.ast;

/**
 * {@code this.foo} &rarr; {@code PropertyAccessExpr("foo")}.
 *
 * <p>The {@code this} receiver is implicit; expressions with an explicit
 * object go through {@link MemberExpr}.
 *
 * <p>{@code sourceLocation} is the {@code this} token (N-463); only the
 * {@code .runar.ts} parser sets it. It is not part of equality.
 */
public record PropertyAccessExpr(String property, SourceLocation sourceLocation) implements Expression {
    public PropertyAccessExpr(String property) {
        this(property, null);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PropertyAccessExpr other && java.util.Objects.equals(property, other.property);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hashCode(property);
    }

    @Override
    public String kind() {
        return "property_access";
    }
}
