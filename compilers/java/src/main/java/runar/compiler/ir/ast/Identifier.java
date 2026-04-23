package runar.compiler.ir.ast;

public record Identifier(String name) implements Expression {
    @Override
    public String kind() {
        return "identifier";
    }
}
