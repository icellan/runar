package runar.lang.types;

/**
 * DER-encoded ECDSA signature (variable length, typically ~72 bytes)
 * over the secp256k1 curve.
 */
public final class Sig extends ByteString {
    public Sig(byte[] bytes) {
        super(bytes);
    }

    public static Sig fromHex(String hex) {
        return new Sig(java.util.HexFormat.of().parseHex(hex));
    }
}
