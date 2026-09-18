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

    /**
     * Frames {@code dataHex} as a state-section field: {@code <len><data>}.
     *
     * <p>Deliberately NOT the MINIMALDATA push encoding used by
     * {@link #encodePushData}. The state section is raw data after
     * {@code OP_RETURN} in the locking script; the interpreter never executes
     * it, so {@code SCRIPT_VERIFY_MINIMALDATA} — a rule applied to push opcodes
     * as they are executed — does not reach it. What does read it is the
     * compiler's on-chain state codec ({@code emitPushDataEncode} in
     * packages/runar-compiler/src/passes/05-stack-lower.ts), which writes and
     * parses {@code <len><data>}. Both sides must agree byte for byte or the
     * continuation hash check fails and the contract is unspendable.
     *
     * <p>#110 applied the MINIMALDATA short-circuit here, in all seven SDKs and
     * none of the seven compilers, so a 1-byte {@code 0x05} state field
     * serialised off-chain as {@code 55} while the script rebuilt it as
     * {@code 0105}. Byte-identical with the other six SDKs.
     */
    public static String encodePushDataState(String dataHex) {
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

    /**
     * Decodes a state-section field at {@code offset} in hex. Returns
     * {@code [fieldHex, hexCharsConsumed]}.
     *
     * <p>Exact inverse of {@link #encodePushDataState}, and deliberately as
     * strict as the compiler's on-chain state reader: only
     * {@code <len><data>} framing is understood. {@code OP_1..OP_16}
     * (0x51..0x60) and {@code OP_1NEGATE} (0x4f) are NOT decoded as
     * single-byte values — accepting them would let the SDK read a state
     * section the contract's own script cannot parse.
     *
     * @throws IllegalArgumentException if the framing is truncated, non-hex, or
     *     not a push at all (C2 — this used to throw a raw
     *     {@link StringIndexOutOfBoundsException} or silently consume a byte).
     */
    public static DecodedPush decodePushDataState(String hex, int offset) {
        need(hex, offset, 2, "push opcode");
        int opcode;
        try {
            opcode = Integer.parseInt(hex.substring(offset, offset + 2), 16);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                "deserializeState: non-hex byte at offset " + (offset / 2) + " in the state section");
        }
        if (opcode <= 75) {
            int dataLen = opcode * 2;
            need(hex, offset, 2 + dataLen, "push payload");
            return new DecodedPush(hex.substring(offset + 2, offset + 2 + dataLen), 2 + dataLen);
        }
        if (opcode == 0x4c) {
            need(hex, offset, 4, "OP_PUSHDATA1 length prefix");
            int length = Integer.parseInt(hex.substring(offset + 2, offset + 4), 16);
            int dataLen = length * 2;
            need(hex, offset, 4 + dataLen, "OP_PUSHDATA1 payload");
            return new DecodedPush(hex.substring(offset + 4, offset + 4 + dataLen), 4 + dataLen);
        }
        if (opcode == 0x4d) {
            need(hex, offset, 6, "OP_PUSHDATA2 length prefix");
            int lo = Integer.parseInt(hex.substring(offset + 2, offset + 4), 16);
            int hi = Integer.parseInt(hex.substring(offset + 4, offset + 6), 16);
            int length = lo | (hi << 8);
            int dataLen = length * 2;
            need(hex, offset, 6 + dataLen, "OP_PUSHDATA2 payload");
            return new DecodedPush(hex.substring(offset + 6, offset + 6 + dataLen), 6 + dataLen);
        }
        if (opcode == 0x4e) {
            need(hex, offset, 10, "OP_PUSHDATA4 length prefix");
            int b0 = Integer.parseInt(hex.substring(offset + 2, offset + 4), 16);
            int b1 = Integer.parseInt(hex.substring(offset + 4, offset + 6), 16);
            int b2 = Integer.parseInt(hex.substring(offset + 6, offset + 8), 16);
            int b3 = Integer.parseInt(hex.substring(offset + 8, offset + 10), 16);
            int length = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            int dataLen = length * 2;
            need(hex, offset, 10 + dataLen, "OP_PUSHDATA4 payload");
            return new DecodedPush(hex.substring(offset + 10, offset + 10 + dataLen), 10 + dataLen);
        }
        // Not a push opcode at all — encodePushDataState can never emit one, so
        // the state section is malformed. This used to consume one byte and
        // return an empty value, desynchronising every subsequent field.
        throw new IllegalArgumentException(String.format(
            "deserializeState: byte 0x%02x at offset %d is not a push opcode; "
                + "the state section is malformed",
            opcode, offset / 2));
    }

    /**
     * Asserts {@code chars} hex chars are available from {@code offset}, else
     * fails closed (C2). Without this every branch above was a bare
     * {@code substring} that threw a raw {@link StringIndexOutOfBoundsException}
     * on a short third-party blob.
     */
    private static void need(String hex, int offset, int chars, String what) {
        if (offset + chars > hex.length()) {
            throw new IllegalArgumentException(String.format(
                "deserializeState: truncated state — %s runs past the end of the state section "
                    + "(needs %d byte(s) at offset %d, only %d remain)",
                what, chars / 2, offset / 2, Math.max(0, hex.length() - offset) / 2));
        }
    }

    /**
     * Encodes {@code dataHex} as a push-data opcode + payload in hex, for
     * pushes the interpreter will EXECUTE (unlocking scripts, spliced
     * constructor args).
     *
     * <p>Applies BSV consensus rule {@code SCRIPT_VERIFY_MINIMALDATA} for
     * single-byte pushes: a 1-byte payload whose value is in
     * {@code {0x01..0x10, 0x81}} MUST use the corresponding minimal opcode
     * ({@code OP_1..OP_16} / {@code OP_1NEGATE}) rather than the direct push
     * {@code 01 NN}. Non-minimal direct pushes are relay-rejected as
     * "Data push larger than necessary".
     *
     * <p>NOTE: {@code 0x00} is deliberately NOT in that set. {@code OP_0}
     * pushes the EMPTY byte array, not a 1-byte {@code 0x00} — so the minimal
     * encoding of a 1-byte {@code 0x00} payload is the direct push
     * {@code 01 00} (matching the compiler's {@code encodePushBytesHex} in
     * push-encoding.ts), not {@code OP_0} (C9 / S1).
     */
    public static String encodePushData(String dataHex) {
        int dataLen = dataHex.length() / 2;
        // MINIMALDATA: single-byte payloads in the OP_N range must use the
        // corresponding minimal opcode. The script-number encoder already
        // short-circuits OP_N for Int fields; this brings the ByteString push
        // path to the same standard so a 1-byte ByteString value does not
        // emit a relay-rejected non-minimal direct push.
        if (dataLen == 1) {
            int b = Integer.parseInt(dataHex, 16);
            if (b >= 0x01 && b <= 0x10) return String.format("%02x", 0x50 + b); // OP_1..OP_16
            if (b == 0x81) return "4f";                              // OP_1NEGATE
        }
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

    /**
     * Decodes a push-data at {@code offset} in hex. Returns
     * {@code [pushedHex, hexCharsConsumed]}.
     *
     * <p>Inverse of {@link #encodePushData}'s MINIMALDATA short-circuit:
     * {@code OP_1..OP_16} (0x51..0x60) and {@code OP_1NEGATE} (0x4f) each push
     * a single byte with no separate data bytes in the script — the opcode
     * itself encodes the value (C9). {@code OP_0} (0x00) falls through to the
     * {@code opcode <= 75} branch and correctly decodes as the empty byte
     * array, since the encoder no longer emits {@code OP_0} for a 1-byte
     * {@code 0x00} payload.
     */
    public static DecodedPush decodePushData(String hex, int offset) {
        int opcode = Integer.parseInt(hex.substring(offset, offset + 2), 16);
        if (opcode >= 0x51 && opcode <= 0x60) {  // OP_1..OP_16
            return new DecodedPush(String.format("%02x", opcode - 0x50), 2);
        }
        if (opcode == 0x4f) {                    // OP_1NEGATE
            return new DecodedPush("81", 2);
        }
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
