package runar.compiler.ir.ast;

public record UnaryExpr(Expression.UnaryOp op, Expression operand) implements Expression {
    @Override
    public String kind() {
        return "unary_expr";
    }
}
