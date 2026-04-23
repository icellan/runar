package runar.compiler.ir.ast;

import java.util.List;

public record CallExpr(Expression callee, List<Expression> args) implements Expression {
    @Override
    public String kind() {
        return "call_expr";
    }
}
