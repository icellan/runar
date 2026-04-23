package runar.compiler.ir.ast;

import java.util.List;

public record ArrayLiteralExpr(List<Expression> elements) implements Expression {
    @Override
    public String kind() {
        return "array_literal";
    }
}
