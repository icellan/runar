package runar.compiler.ir.ast;

/**
 * {@code let name[: type] = init;}
 *
 * <p>{@code type} is nullable — the parser may omit it, relying on the
 * type-checker to infer from {@code init}.
 */
public record VariableDeclStatement(
    String name,
    TypeNode type,
    Expression init,
    SourceLocation sourceLocation
) implements Statement {
    @Override
    public String kind() {
        return "variable_decl";
    }
}
