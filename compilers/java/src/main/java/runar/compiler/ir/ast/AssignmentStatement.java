package runar.compiler.ir.ast;

public record AssignmentStatement(
    Expression target,
    Expression value,
    SourceLocation sourceLocation
) implements Statement {
    @Override
    public String kind() {
        return "assignment";
    }
}
