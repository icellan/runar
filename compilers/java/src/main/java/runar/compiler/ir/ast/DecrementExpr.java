package runar.compiler.ir.ast;

public record DecrementExpr(Expression operand, boolean prefix) implements Expression {
    @Override
    public String kind() {
        return "decrement_expr";
    }
}
