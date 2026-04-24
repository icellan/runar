package runar.lang.types;

/**
 * 20-byte RIPEMD-160 digest. Distinct type name from {@link Addr}, but the
 * Rúnar type system treats {@code Addr} as an alias for
 * {@code Ripemd160} — they have the same wire format (20 bytes) and the
 * compiler enforces the length constraint during validation.
 */
public final class Ripemd160 extends ByteString {
    public Ripemd160(byte[] bytes) {
        super(bytes);
    }

    public static Ripemd160 fromHex(String hex) {
        return new Ripemd160(java.util.HexFormat.of().parseHex(hex));
    }
}
