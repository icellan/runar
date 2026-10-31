package runar.compiler.ir.ast;

/**
 * A binary operation like {@code a + b}.
 *
 * <p>{@code sourceLocation} is where the expression starts, including a
 * leading {@code (} (N-472). Only the {@code .runar.ts} parser sets it, as the
 * TS reference does; elsewhere it is {@code null} and typecheck falls back to
 * the leftmost leaf. It is not part of equality.
 */
public record BinaryExpr(Expression.BinaryOp op, Expression left, Expression right, SourceLocation sourceLocation)
        implements Expression {
    public BinaryExpr(Expression.BinaryOp op, Expression left, Expression right) {
        this(op, left, right, null);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof BinaryExpr other
            && op == other.op
            && java.util.Objects.equals(left, other.left)
            && java.util.Objects.equals(right, other.right);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(op, left, right);
    }

    @Override
    public String kind() {
        return "binary_expr";
    }
}
