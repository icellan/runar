package runar.compiler.ir.ast;

/**
 * {@code return [value];}. {@code value} is nullable for a bare {@code return}.
 */
public record ReturnStatement(
    Expression value,
    SourceLocation sourceLocation
) implements Statement {
    @Override
    public String kind() {
        return "return_statement";
    }
}
