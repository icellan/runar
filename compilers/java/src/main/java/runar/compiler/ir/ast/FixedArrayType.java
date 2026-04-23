package runar.compiler.ir.ast;

public record FixedArrayType(TypeNode element, int length) implements TypeNode {
    @Override
    public String kind() {
        return "fixed_array_type";
    }
}
