package runar.compiler.ir.ast;

public record BinaryExpr(Expression.BinaryOp op, Expression left, Expression right) implements Expression {
    @Override
    public String kind() {
        return "binary_expr";
    }
}
