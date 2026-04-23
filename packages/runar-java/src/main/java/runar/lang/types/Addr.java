package runar.lang.types;

/**
 * 20-byte HASH160 digest used as a Bitcoin address. Alias for
 * {@code Ripemd160} in the Rúnar type system. The compiler enforces the
 * 20-byte length constraint during validation.
 */
public final class Addr extends ByteString {
    public Addr(byte[] bytes) {
        super(bytes);
    }

    public static Addr fromHex(String hex) {
        return new Addr(java.util.HexFormat.of().parseHex(hex));
    }
}
