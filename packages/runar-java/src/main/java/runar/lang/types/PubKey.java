package runar.lang.types;

/**
 * 33-byte compressed secp256k1 public key. The compiler enforces the
 * length constraint during validation.
 */
public final class PubKey extends ByteString {
    public PubKey(byte[] bytes) {
        super(bytes);
    }

    public static PubKey fromHex(String hex) {
        return new PubKey(java.util.HexFormat.of().parseHex(hex));
    }
}
