package runar.compiler.ir.ast;

public record PrimitiveType(PrimitiveTypeName name) implements TypeNode {
    @Override
    public String kind() {
        return "primitive_type";
    }
}
