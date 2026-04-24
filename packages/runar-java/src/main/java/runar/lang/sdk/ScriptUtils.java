package runar.lang.sdk;

import java.util.HexFormat;

/**
 * Bitcoin Script push-data / varint helpers. Hex-oriented like the Go
 * and Rust SDKs — the SDK works with hex-encoded locking scripts
 * throughout.
 */
public final class ScriptUtils {
    private static final HexFormat HEX = HexFormat.of();

    private ScriptUtils() {}

    /** Encodes {@code dataHex} as a push-data opcode + payload in hex. */
    public static String encodePushData(String dataHex) {
        int dataLen = dataHex.length() / 2;
        if (dataLen <= 75) {
            return String.format("%02x", dataLen) + dataHex;
        }
        if (dataLen <= 0xff) {
            return "4c" + String.format("%02x", dataLen) + dataHex;
        }
        if (dataLen <= 0xffff) {
            int lo = dataLen & 0xff;
            int hi = (dataLen >> 8) & 0xff;
            return "4d" + String.format("%02x%02x", lo, hi) + dataHex;
        }
        int b0 = dataLen & 0xff;
        int b1 = (dataLen >> 8) & 0xff;
        int b2 = (dataLen >> 16) & 0xff;
        int b3 = (dataLen >> 24) & 0xff;
        return "4e" + String.format("%02x%02x%02x%02x", b0, b1, b2, b3) + dataHex;
    }

    /** Decodes a push-data at {@code offset} in hex. Returns {@code [pushedHex, hexCharsConsumed]}. */
    public static DecodedPush decodePushData(String hex, int offset) {
        int opcode = Integer.parseInt(hex.substring(offset, offset + 2), 16);
        if (opcode <= 75) {
            int dataLen = opcode * 2;
            return new DecodedPush(hex.substring(offset + 2, offset + 2 + dataLen), 2 + dataLen);
        }
        if (opcode == 0x4c) {
            int length = Integer.parseInt(hex.substring(offset + 2, offset + 4), 16);
            int dataLen = length * 2;
            return new DecodedPush(hex.substring(offset + 4, offset + 4 + dataLen), 4 + dataLen);
        }
        if (opcode == 0x4d) {
            int lo = Integer.parseInt(hex.substring(offset + 2, offset + 4), 16);
            int hi = Integer.parseInt(hex.substring(offset + 4, offset + 6), 16);
            int length = lo | (hi << 8);
            int dataLen = length * 2;
            return new DecodedPush(hex.substring(offset + 6, offset + 6 + dataLen), 6 + dataLen);
        }
        if (opcode == 0x4e) {
            int b0 = Integer.parseInt(hex.substring(offset + 2, offset + 4), 16);
            int b1 = Integer.parseInt(hex.substring(offset + 4, offset + 6), 16);
            int b2 = Integer.parseInt(hex.substring(offset + 6, offset + 8), 16);
            int b3 = Integer.parseInt(hex.substring(offset + 8, offset + 10), 16);
            int length = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            int dataLen = length * 2;
            return new DecodedPush(hex.substring(offset + 10, offset + 10 + dataLen), 10 + dataLen);
        }
        return new DecodedPush("", 2);
    }

    public record DecodedPush(String dataHex, int hexCharsConsumed) {}

    /** Encodes an {@code n}-byte varint as hex. */
    public static String encodeVarInt(long n) {
        if (n < 0xfdL) return String.format("%02x", n);
        if (n <= 0xffffL) {
            return "fd" + String.format("%02x", n & 0xff) + String.format("%02x", (n >> 8) & 0xff);
        }
        if (n <= 0xffffffffL) {
            return "fe" + toLittleEndian32((int) n);
        }
        return "ff" + toLittleEndian64(n);
    }

    public static String toLittleEndian32(int n) {
        return String.format("%02x%02x%02x%02x",
            n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff);
    }

    public static String toLittleEndian64(long n) {
        return toLittleEndian32((int) (n & 0xffffffffL)) + toLittleEndian32((int) ((n >> 32) & 0xffffffffL));
    }

    public static String reverseHex(String hex) {
        char[] chars = new char[hex.length()];
        int n = hex.length();
        for (int i = 0; i < n; i += 2) {
            chars[n - 2 - i] = hex.charAt(i);
            chars[n - 1 - i] = hex.charAt(i + 1);
        }
        return new String(chars);
    }

    public static byte[] hexToBytes(String hex) {
        return HEX.parseHex(hex);
    }

    public static String bytesToHex(byte[] b) {
        return HEX.formatHex(b);
    }

    /**
     * Walks a hex-encoded script and returns the offset of the last
     * OP_RETURN (0x6a) at an opcode boundary, or -1. Skips push data
     * so inner 0x6a bytes are not matched.
     */
    public static int findLastOpReturn(String scriptHex) {
        int offset = 0;
        int length = scriptHex.length();
        while (offset + 2 <= length) {
            int opcode = Integer.parseInt(scriptHex.substring(offset, offset + 2), 16);
            if (opcode == 0x6a) return offset;
            if (opcode >= 0x01 && opcode <= 0x4b) {
                offset += 2 + opcode * 2;
            } else if (opcode == 0x4c) {
                if (offset + 4 > length) break;
                int pushLen = Integer.parseInt(scriptHex.substring(offset + 2, offset + 4), 16);
                offset += 4 + pushLen * 2;
            } else if (opcode == 0x4d) {
                if (offset + 6 > length) break;
                int lo = Integer.parseInt(scriptHex.substring(offset + 2, offset + 4), 16);
                int hi = Integer.parseInt(scriptHex.substring(offset + 4, offset + 6), 16);
                int pushLen = lo | (hi << 8);
                offset += 6 + pushLen * 2;
            } else if (opcode == 0x4e) {
                if (offset + 10 > length) break;
                int b0 = Integer.parseInt(scriptHex.substring(offset + 2, offset + 4), 16);
                int b1 = Integer.parseInt(scriptHex.substring(offset + 4, offset + 6), 16);
                int b2 = Integer.parseInt(scriptHex.substring(offset + 6, offset + 8), 16);
                int b3 = Integer.parseInt(scriptHex.substring(offset + 8, offset + 10), 16);
                int pushLen = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
                offset += 10 + pushLen * 2;
            } else {
                offset += 2;
            }
        }
        return -1;
    }

    /**
     * Builds a standard P2PKH locking script from an address, pubkey
     * hash, or public key — parity with Go {@code BuildP2PKHScript}.
     * <ul>
     *   <li>40 hex chars → raw pubkey hash</li>
     *   <li>66 / 130 hex chars → compressed / uncompressed pubkey, hashed</li>
     *   <li>otherwise → Base58Check address</li>
     * </ul>
     */
    public static String buildP2PKHScript(String addressOrKey) {
        String pkh;
        if (addressOrKey.length() == 40 && isHex(addressOrKey)) {
            pkh = addressOrKey;
        } else if ((addressOrKey.length() == 66 || addressOrKey.length() == 130) && isHex(addressOrKey)) {
            byte[] pubKey = HEX.parseHex(addressOrKey);
            pkh = HEX.formatHex(Hash160.hash160(pubKey));
        } else {
            byte[] h = Base58Check.decodeP2PKH(addressOrKey);
            pkh = HEX.formatHex(h);
        }
        return "76a914" + pkh + "88ac";
    }

    public static boolean isHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
        }
        return true;
    }
}
