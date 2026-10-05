package runar.lang.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ScriptUtilsTest {

    @Test
    void encodePushDataUsesDirectPushForSmallPayload() {
        assertEquals("02aabb", ScriptUtils.encodePushData("aabb"));
    }

    @Test
    void encodePushDataUsesOp_PUSHDATA1For76PlusBytes() {
        String data = "aa".repeat(76);
        String out = ScriptUtils.encodePushData(data);
        assertEquals("4c4c" + data, out);
    }

    // MINIMALDATA (SCRIPT_VERIFY_MINIMALDATA): a 1-byte payload in
    // {0x01..0x10, 0x81} must use the minimal opcode, not a direct push.
    // 0x00 is NOT in that set: OP_0 pushes the EMPTY byte array, so the
    // minimal encoding of a 1-byte 0x00 is the direct push `01 00` —
    // matching the compiler's encodePushBytesHex (C9 / S1).
    @Test
    void encodePushDataMinimalDataSingleByte() {
        assertEquals("0100", ScriptUtils.encodePushData("00")); // direct push, NOT OP_0
        assertEquals("55", ScriptUtils.encodePushData("05")); // OP_5
        assertEquals("4f", ScriptUtils.encodePushData("81")); // OP_1NEGATE
        for (int n = 1; n <= 16; n++) {
            assertEquals(String.format("%02x", 0x50 + n),
                ScriptUtils.encodePushData(String.format("%02x", n)));
        }
    }

    @Test
    void encodePushDataMinimalDataBoundariesStillDirectPush() {
        // Single bytes outside the OP_N range still direct-push.
        for (int b : new int[]{0x11, 0x4f, 0x50, 0x60, 0x80, 0x82, 0xff}) {
            assertEquals(String.format("01%02x", b),
                ScriptUtils.encodePushData(String.format("%02x", b)));
        }
        // Two-byte payloads are unaffected.
        assertEquals("020011", ScriptUtils.encodePushData("0011"));
    }

    @Test
    void decodePushDataRoundTrips() {
        String data = "deadbeef";
        String encoded = ScriptUtils.encodePushData(data);
        ScriptUtils.DecodedPush got = ScriptUtils.decodePushData(encoded, 0);
        assertEquals(data, got.dataHex());
        assertEquals(encoded.length(), got.hexCharsConsumed());
    }

    // -----------------------------------------------------------------------
    // F-238 — decodePushData must refuse malformed provider-supplied scripts
    // instead of throwing a raw StringIndexOutOfBoundsException / NumberFormat
    // Exception or silently returning a truncated/empty payload.
    //
    // decodePushDataState (the on-chain state-section reader in this same
    // file) already bounds-checks via `need()` and throws a clear
    // IllegalArgumentException (C2); decodePushData -- used by
    // ContractScript.extractConstructorArgs for the SAME kind of
    // provider-supplied-script parsing -- did not. This mirrors that
    // established pattern rather than inventing a new one.
    //
    // PROVES: every vector in the brief's testable assertion throws
    // IllegalArgumentException with a clear message, and a valid push of
    // every pushdata flavour still decodes unchanged.
    // DOES NOT PROVE: fail-closed behaviour of any other script reader in
    // this package.
    // -----------------------------------------------------------------------

    private static final String[] F238_MALFORMED_VECTORS = {
        "",           // no opcode byte at all
        "f",          // odd-length hex, can't even form an opcode byte
        "05aabb",     // direct push declares 5 bytes, only 2 remain
        "4c",         // OP_PUSHDATA1 with no length byte
        "4c05aa",     // OP_PUSHDATA1 declares 5 bytes, only 1 remains
        "4d0100",     // OP_PUSHDATA2 length prefix present, 0 of the 1 declared bytes remain
        "4e01000000", // OP_PUSHDATA4 length prefix present, 0 of the 1 declared bytes remain
    };

    @Test
    void decodePushDataRefusesEveryMalformedVector() {
        for (String hex : F238_MALFORMED_VECTORS) {
            assertThrows(IllegalArgumentException.class, () -> ScriptUtils.decodePushData(hex, 0),
                "decodePushData(" + hex + "): want IllegalArgumentException");
        }
    }

    @Test
    void decodePushDataStillDecodesValidPushesOfEveryFlavour() {
        assertEquals("2a", ScriptUtils.decodePushData("012a", 0).dataHex());
        assertEquals(4, ScriptUtils.decodePushData("012a", 0).hexCharsConsumed());

        assertEquals("2a", ScriptUtils.decodePushData("4c012a", 0).dataHex());
        assertEquals(6, ScriptUtils.decodePushData("4c012a", 0).hexCharsConsumed());

        assertEquals("2a", ScriptUtils.decodePushData("4d01002a", 0).dataHex());
        assertEquals(8, ScriptUtils.decodePushData("4d01002a", 0).hexCharsConsumed());

        assertEquals("2a", ScriptUtils.decodePushData("4e010000002a", 0).dataHex());
        assertEquals(12, ScriptUtils.decodePushData("4e010000002a", 0).hexCharsConsumed());
    }

    @Test
    void findLastOpReturnSkipsPushData() {
        // Directly push a 0x6a byte, then a real OP_RETURN afterwards.
        String script = ScriptUtils.encodePushData("6a") + "6a";
        int pos = ScriptUtils.findLastOpReturn(script);
        assertEquals(script.length() - 2, pos);
    }

    @Test
    void buildP2PKHFromPubKeyHashHex() {
        String pkh = "00".repeat(20);
        assertEquals("76a914" + pkh + "88ac", ScriptUtils.buildP2PKHScript(pkh));
    }

    @Test
    void reverseHexFlipsByteOrder() {
        assertEquals("ddccbbaa", ScriptUtils.reverseHex("aabbccdd"));
    }

    @Test
    void varIntRoundTrip() {
        // Values at the boundaries of each width.
        assertEquals("00", ScriptUtils.encodeVarInt(0));
        assertEquals("fc", ScriptUtils.encodeVarInt(0xfc));
        assertEquals("fdfd00", ScriptUtils.encodeVarInt(0xfd));
        assertEquals("fdffff", ScriptUtils.encodeVarInt(0xffff));
    }
}
