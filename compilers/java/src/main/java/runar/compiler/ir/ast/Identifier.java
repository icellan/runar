package runar.compiler.ir.ast;

/**
 * A variable or name reference.
 *
 * <p>{@code sourceLocation} is the identifier's token (N-463). Every surface
 * parser sets it, as the TS reference does; a synthesized identifier carries
 * {@code null}. It is not part of equality: two identifiers naming the same
 * thing are the same identifier wherever they were written.
 */
public record Identifier(String name, SourceLocation sourceLocation) implements Expression {
    public Identifier(String name) {
        this(name, null);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Identifier other && java.util.Objects.equals(name, other.name);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hashCode(name);
    }

    @Override
    public String kind() {
        return "identifier";
    }
}
