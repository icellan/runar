package runar.compiler.ir.ast;

public record IndexAccessExpr(Expression object, Expression index) implements Expression {
    @Override
    public String kind() {
        return "index_access";
    }
}
