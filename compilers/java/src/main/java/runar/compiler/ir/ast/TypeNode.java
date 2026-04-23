package runar.compiler.ir.ast;

/**
 * Type nodes in the Rúnar AST. The type system is closed at the
 * primitive level (see {@link PrimitiveTypeName}); user-defined types
 * exist only as {@link CustomType} placeholders resolved by the
 * type-checker.
 *
 * <p>Mirrors {@code TypeNode} in {@code packages/runar-ir-schema/src/runar-ast.ts}.
 */
public sealed interface TypeNode permits PrimitiveType, FixedArrayType, CustomType {
    String kind();
}
