package runar.lang.types;

/**
 * 32-byte SHA-256 digest. In the Rúnar type system the canonical name is
 * {@code Sha256}; this Java class is called {@code Sha256Digest} so the
 * identifier {@code Sha256} remains free for a future hash-function
 * intrinsic in {@link runar.lang.Builtins}. Use {@link Sha256} as a
 * short-hand alias — it is a separate final class that extends this one.
 */
public class Sha256Digest extends ByteString {
    public Sha256Digest(byte[] bytes) {
        super(bytes);
    }

    public static Sha256Digest fromHex(String hex) {
        return new Sha256Digest(java.util.HexFormat.of().parseHex(hex));
    }
}
