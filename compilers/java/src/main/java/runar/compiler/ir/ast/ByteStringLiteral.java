package runar.compiler.ir.ast;

/**
 * Byte-string literal; {@code value} is hex-encoded without a leading {@code 0x}.
 *
 * <p>{@code sourceLocation} is the literal's opening quote (N-432). Only the
 * {@code .runar.ts} parser sets it, as the TS reference does; elsewhere it is
 * {@code null} and the hex diagnostics print no location.
 */
public record ByteStringLiteral(String value, SourceLocation sourceLocation) implements Expression {
    public ByteStringLiteral(String value) {
        this(value, null);
    }

    @Override
    public String kind() {
        return "bytestring_literal";
    }
}
