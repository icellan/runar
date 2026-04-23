package runar.compiler.ir.ast;

/** Byte-string literal; {@code value} is hex-encoded without a leading {@code 0x}. */
public record ByteStringLiteral(String value) implements Expression {
    @Override
    public String kind() {
        return "bytestring_literal";
    }
}
