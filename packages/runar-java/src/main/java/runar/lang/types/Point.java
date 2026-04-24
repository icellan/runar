package runar.lang.types;

/**
 * secp256k1 elliptic-curve point — 64 bytes (x[32] || y[32], big-endian
 * unsigned, no 0x04 prefix). Produced by {@code ecMakePoint},
 * {@code ecMulGen}, and the {@code ecAdd}/{@code ecMul} builtins. The
 * compiler enforces the 64-byte length constraint during validation.
 */
public final class Point extends ByteString {
    public Point(byte[] bytes) {
        super(bytes);
    }

    public static Point fromHex(String hex) {
        return new Point(java.util.HexFormat.of().parseHex(hex));
    }
}
