package runar.lang.types;

/**
 * NIST P-256 (secp256r1) elliptic-curve point — 64 bytes
 * (x[32] || y[32], big-endian unsigned, no prefix). Used by the
 * {@code p256-wallet} and {@code schnorr-zkp} reference contracts.
 */
public final class P256Point extends ByteString {
    public P256Point(byte[] bytes) {
        super(bytes);
    }

    public static P256Point fromHex(String hex) {
        return new P256Point(java.util.HexFormat.of().parseHex(hex));
    }
}
