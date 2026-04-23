package runar.compiler.ir.ast;

/**
 * {@code this.foo} &rarr; {@code PropertyAccessExpr("foo")}.
 *
 * <p>The {@code this} receiver is implicit; expressions with an explicit
 * object go through {@link MemberExpr}.
 */
public record PropertyAccessExpr(String property) implements Expression {
    @Override
    public String kind() {
        return "property_access";
    }
}
