package runar.lang.types;

/**
 * NIST P-384 (secp384r1) elliptic-curve point — 96 bytes
 * (x[48] || y[48], big-endian unsigned, no prefix). Used by the
 * {@code p384-wallet} reference contract.
 */
public final class P384Point extends ByteString {
    public P384Point(byte[] bytes) {
        super(bytes);
    }

    public static P384Point fromHex(String hex) {
        return new P384Point(java.util.HexFormat.of().parseHex(hex));
    }
}
