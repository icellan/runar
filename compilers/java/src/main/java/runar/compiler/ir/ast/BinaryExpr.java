package runar.compiler.ir.ast;

/**
 * A binary operation like {@code a + b}.
 *
 * <p>{@code sourceLocation} is where the expression starts, including a
 * leading {@code (} (N-472). Every surface parser sets it, as the TS reference
 * does; a node a parser synthesizes carries {@code null} and typecheck falls
 * back to the leftmost leaf. It is not part of equality.
 */
public record BinaryExpr(
    Expression.BinaryOp op,
    Expression left,
    Expression right,
    SourceLocation sourceLocation,
    /** D12 FE-F1: see {@link OperandTypeSlot}. Never null; not part of equality. */
    OperandTypeSlot operandType
) implements Expression {
    public BinaryExpr {
        if (operandType == null) operandType = new OperandTypeSlot();
    }

    public BinaryExpr(Expression.BinaryOp op, Expression left, Expression right, SourceLocation sourceLocation) {
        this(op, left, right, sourceLocation, new OperandTypeSlot());
    }

    public BinaryExpr(Expression.BinaryOp op, Expression left, Expression right) {
        this(op, left, right, null, new OperandTypeSlot());
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
