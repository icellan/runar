package runar.compiler.ir.ast;

public record ParamNode(String name, TypeNode type) {
    public String kind() {
        return "param";
    }
}
