package runar.lang.sdk;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Base58Check round-trip tests for mainnet P2PKH addresses (version
 * byte 0x00). Cross-validates against well-known test vectors so any
 * regression in the alphabet, leading-zero handling, or checksum logic
 * is caught immediately.
 */
class Base58CheckTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void encodesGenesisCoinbasePubkeyHashToKnownAddress() {
        // Hash160 of Satoshi's coinbase pubkey:
        // 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
        // → hash160 = 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 (well known).
        byte[] pkh = HEX.parseHex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
        String addr = Base58Check.encodeMainnetP2PKH(pkh);
        assertEquals("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", addr);
    }

    @Test
    void decodeRoundTrip() {
        byte[] pkh = HEX.parseHex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
        String addr = Base58Check.encodeMainnetP2PKH(pkh);
        assertArrayEquals(pkh, Base58Check.decodeP2PKH(addr));
    }

    @Test
    void rejectsBadHashLength() {
        assertThrows(IllegalArgumentException.class,
            () -> Base58Check.encodeMainnetP2PKH(new byte[19]));
        assertThrows(IllegalArgumentException.class,
            () -> Base58Check.encodeMainnetP2PKH(new byte[21]));
    }

    @Test
    void decodeRejectsTamperedAddress() {
        byte[] pkh = HEX.parseHex("00".repeat(20));
        String addr = Base58Check.encodeMainnetP2PKH(pkh);
        // Flip a digit somewhere in the middle (index 5 is past the prefix run).
        char[] chars = addr.toCharArray();
        chars[5] = chars[5] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);
        assertThrows(RuntimeException.class, () -> Base58Check.decodeP2PKH(tampered));
    }

    @Test
    void leadingZeroByteEncodedAsLeading1() {
        // hash160 = 00..00 → address starts with '1' (the Base58 0).
        byte[] zeros = new byte[20];
        String addr = Base58Check.encodeMainnetP2PKH(zeros);
        // Mainnet version 0x00 + 20 zero bytes → many leading zeros, so
        // the address has a long '1' prefix.
        assertTrue(addr.startsWith("11111111"), "all-zero hash must produce address with '111111...' prefix, got " + addr);
    }
}
