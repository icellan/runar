package runar.compiler.ir.ast;

/**
 * A unary operation like {@code !a}, {@code -a}, {@code ~a}.
 *
 * <p>{@code sourceLocation} is the operator token (N-472); every surface
 * parser sets it for operator-syntax unaries, and a synthesized unary carries
 * {@code null}. It is not part of equality.
 */
public record UnaryExpr(
    Expression.UnaryOp op,
    Expression operand,
    SourceLocation sourceLocation,
    /** D12 FE-F1: see {@link OperandTypeSlot} ({@code ~} only). Never null; not part of equality. */
    OperandTypeSlot operandType
) implements Expression {
    public UnaryExpr {
        if (operandType == null) operandType = new OperandTypeSlot();
    }

    public UnaryExpr(Expression.UnaryOp op, Expression operand, SourceLocation sourceLocation) {
        this(op, operand, sourceLocation, new OperandTypeSlot());
    }

    public UnaryExpr(Expression.UnaryOp op, Expression operand) {
        this(op, operand, null, new OperandTypeSlot());
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
