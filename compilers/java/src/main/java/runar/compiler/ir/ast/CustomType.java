package runar.compiler.ir.ast;

public record CustomType(String name) implements TypeNode {
    @Override
    public String kind() {
        return "custom_type";
    }
}
