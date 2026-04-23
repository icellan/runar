package runar.compiler.ir.ast;

import java.util.List;

public record ForStatement(
    VariableDeclStatement init,
    Expression condition,
    Statement update,
    List<Statement> body,
    SourceLocation sourceLocation
) implements Statement {
    @Override
    public String kind() {
        return "for_statement";
    }
}
