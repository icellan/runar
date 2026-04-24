package runar.lang.types;

/**
 * Short-hand alias for {@link Sha256Digest}. Both names are recognised by
 * the parser (via {@link runar.compiler.ir.ast.PrimitiveTypeName}).
 * Prefer {@code Sha256} in contract source for brevity; use
 * {@code Sha256Digest} when you want to emphasise that a value is a
 * digest rather than a call to a hash function.
 */
public final class Sha256 extends Sha256Digest {
    public Sha256(byte[] bytes) {
        super(bytes);
    }

    public static Sha256 fromHex(String hex) {
        return new Sha256(java.util.HexFormat.of().parseHex(hex));
    }
}
