package runar.compiler.ir.ast;

import java.util.List;

/**
 * {@code if (cond) { then } else { else }}. {@code elseBody} is nullable
 * for an {@code if} without an {@code else} clause.
 */
public record IfStatement(
    Expression condition,
    List<Statement> thenBody,
    List<Statement> elseBody,
    SourceLocation sourceLocation
) implements Statement {
    @Override
    public String kind() {
        return "if_statement";
    }
}
