package runar.lang.sdk;

import java.math.BigInteger;

/** Minimal Base58Check encoder / decoder for P2PKH addresses. */
final class Base58Check {
    private static final char[] ALPHABET =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int[] INDEXES = new int[128];
    static {
        for (int i = 0; i < INDEXES.length; i++) INDEXES[i] = -1;
        for (int i = 0; i < ALPHABET.length; i++) INDEXES[ALPHABET[i]] = i;
    }

    private Base58Check() {}

    /** Encodes a 20-byte pubkey hash as a mainnet (0x00) P2PKH address. */
    static String encodeMainnetP2PKH(byte[] pubKeyHash20) {
        if (pubKeyHash20.length != 20) {
            throw new IllegalArgumentException("pubkey hash must be 20 bytes");
        }
        byte[] payload = new byte[21];
        payload[0] = 0x00;
        System.arraycopy(pubKeyHash20, 0, payload, 1, 20);
        byte[] checksum = Hash160.doubleSha256(payload);
        byte[] full = new byte[25];
        System.arraycopy(payload, 0, full, 0, 21);
        System.arraycopy(checksum, 0, full, 21, 4);
        return encode(full);
    }

    /**
     * Returns the 20-byte pubkey hash from a P2PKH address. Accepts both
     * mainnet (version byte 0x00, addresses starting with `1`) and
     * testnet/regtest (version byte 0x6f, addresses starting with `m`/`n`)
     * encodings. The SDK and integration tests both call into here, and
     * regtest-backed integration suites need the testnet form to match
     * what `importaddress` / `listunspent` use on the node.
     */
    static byte[] decodeP2PKH(String address) {
        byte[] decoded = decode(address);
        if (decoded.length != 25) {
            throw new IllegalArgumentException("Base58Check: decoded length != 25");
        }
        byte[] payload = new byte[21];
        System.arraycopy(decoded, 0, payload, 0, 21);
        byte[] checksum = Hash160.doubleSha256(payload);
        for (int i = 0; i < 4; i++) {
            if (checksum[i] != decoded[21 + i]) {
                throw new IllegalArgumentException("Base58Check: checksum mismatch");
            }
        }
        byte version = payload[0];
        if (version != 0x00 && version != 0x6f) {
            throw new IllegalArgumentException(
                "Base58Check: unsupported P2PKH version byte 0x"
                    + String.format("%02x", version & 0xff));
        }
        byte[] h = new byte[20];
        System.arraycopy(payload, 1, h, 0, 20);
        return h;
    }

    /**
     * Base58Check-decodes the input and returns the payload (the bytes preceding
     * the trailing 4-byte SHA256d checksum). Throws if the checksum does not match
     * or the encoded form is shorter than 4 bytes.
     */
    static byte[] decodeChecked(String input) {
        byte[] decoded = decode(input);
        if (decoded.length < 4) {
            throw new IllegalArgumentException("Base58Check: input too short for checksum");
        }
        int payloadLen = decoded.length - 4;
        byte[] payload = new byte[payloadLen];
        System.arraycopy(decoded, 0, payload, 0, payloadLen);
        byte[] checksum = Hash160.doubleSha256(payload);
        for (int i = 0; i < 4; i++) {
            if (checksum[i] != decoded[payloadLen + i]) {
                throw new IllegalArgumentException("Base58Check: checksum mismatch");
            }
        }
        return payload;
    }

    private static String encode(byte[] input) {
        if (input.length == 0) return "";
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) zeros++;

        BigInteger bi = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        BigInteger base = BigInteger.valueOf(58);
        while (bi.signum() > 0) {
            BigInteger[] dr = bi.divideAndRemainder(base);
            sb.append(ALPHABET[dr[1].intValue()]);
            bi = dr[0];
        }
        for (int i = 0; i < zeros; i++) sb.append(ALPHABET[0]);
        return sb.reverse().toString();
    }

    private static byte[] decode(String input) {
        if (input.isEmpty()) return new byte[0];
        BigInteger bi = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(58);
        int zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == ALPHABET[0]) zeros++;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= INDEXES.length || INDEXES[c] < 0) {
                throw new IllegalArgumentException("Base58Check: invalid character '" + c + "'");
            }
            bi = bi.multiply(base).add(BigInteger.valueOf(INDEXES[c]));
        }
        byte[] bytes = bi.toByteArray();
        // Strip sign byte.
        int start = (bytes.length > 0 && bytes[0] == 0) ? 1 : 0;
        byte[] out = new byte[(bytes.length - start) + zeros];
        System.arraycopy(bytes, start, out, zeros, bytes.length - start);
        return out;
    }
}
