package runar.compiler.ir.ast;

/**
 * A unary operation like {@code !a}, {@code -a}, {@code ~a}.
 *
 * <p>{@code sourceLocation} is the operator token (N-472); only the
 * {@code .runar.ts} parser sets it, elsewhere it is {@code null}. It is not
 * part of equality.
 */
public record UnaryExpr(Expression.UnaryOp op, Expression operand, SourceLocation sourceLocation)
        implements Expression {
    public UnaryExpr(Expression.UnaryOp op, Expression operand) {
        this(op, operand, null);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof UnaryExpr other
            && op == other.op
            && java.util.Objects.equals(operand, other.operand);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(op, operand);
    }

    @Override
    public String kind() {
        return "unary_expr";
    }
}
