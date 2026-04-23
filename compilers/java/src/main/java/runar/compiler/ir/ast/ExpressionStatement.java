package runar.compiler.ir.ast;

public record ExpressionStatement(
    Expression expression,
    SourceLocation sourceLocation
) implements Statement {
    @Override
    public String kind() {
        return "expression_statement";
    }
}
