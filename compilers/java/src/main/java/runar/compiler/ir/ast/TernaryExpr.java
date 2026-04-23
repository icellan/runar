package runar.compiler.ir.ast;

public record TernaryExpr(Expression condition, Expression consequent, Expression alternate) implements Expression {
    @Override
    public String kind() {
        return "ternary_expr";
    }
}
