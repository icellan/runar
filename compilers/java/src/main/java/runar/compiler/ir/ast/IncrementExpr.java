package runar.compiler.ir.ast;

public record IncrementExpr(Expression operand, boolean prefix) implements Expression {
    @Override
    public String kind() {
        return "increment_expr";
    }
}
