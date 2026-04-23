package runar.lang.types;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * Arbitrary-length byte string, the base type for every domain type in
 * the Rúnar type system (Addr, Sig, PubKey, etc.). Immutable.
 *
 * <p>Equality is value-based over the underlying bytes.
 */
public class ByteString {

    private static final HexFormat HEX = HexFormat.of();

    private final byte[] bytes;

    public ByteString(byte[] bytes) {
        this.bytes = bytes.clone();
    }

    public static ByteString fromHex(String hex) {
        return new ByteString(HEX.parseHex(hex));
    }

    public byte[] toByteArray() {
        return bytes.clone();
    }

    public int length() {
        return bytes.length;
    }

    public String toHex() {
        return HEX.formatHex(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ByteString that)) return false;
        return Arrays.equals(this.bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return toHex();
    }
}
