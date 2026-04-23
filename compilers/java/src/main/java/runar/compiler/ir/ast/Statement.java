package runar.compiler.ir.ast;

/**
 * Rúnar statement nodes. Mirrors {@code Statement} in
 * {@code packages/runar-ir-schema/src/runar-ast.ts}.
 */
public sealed interface Statement
    permits VariableDeclStatement, AssignmentStatement, IfStatement,
            ForStatement, ReturnStatement, ExpressionStatement {
    String kind();
    SourceLocation sourceLocation();
}
