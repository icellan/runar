package runar.compiler.ir.ast;

public record BoolLiteral(boolean value) implements Expression {
    @Override
    public String kind() {
        return "bool_literal";
    }
}
