package runar.compiler.ir.ast;

public record MemberExpr(Expression object, String property) implements Expression {
    @Override
    public String kind() {
        return "member_expr";
    }
}
