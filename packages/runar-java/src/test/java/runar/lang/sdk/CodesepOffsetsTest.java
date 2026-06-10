package runar.lang.sdk;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Issue #42: terminal-method sighash subscript byte-walker.
 *
 * <p>The on-chain script trims its sighash subscript at the method's
 * OP_CODESEPARATOR. {@link RunarContract#findCodesepOffsets(String)} must
 * recover the true byte position by walking the script, correctly skipping
 * push-data (which may itself contain a 0xab byte) and all BSV push opcodes.
 */
class CodesepOffsetsTest {

    @Test
    void returnsRealBytePositionSkippingPushData() {
        // 51            OP_1
        // 02 ab cd      push 2 bytes (0xab inside push-data, must be ignored)
        // ab            OP_CODESEPARATOR  <- real, byte offset 4
        // ac            OP_CHECKSIG
        assertEquals(List.of(4), RunarContract.findCodesepOffsets("5102abcdabac"));
    }

    @Test
    void handlesPushData1() {
        // 4c (OP_PUSHDATA1) 02 (len) abab (data, contains 0xab) ab (real codesep)
        assertEquals(List.of(4), RunarContract.findCodesepOffsets("4c02ababab"));
    }

    @Test
    void trimsSubscriptAtRealCodesepBytePosition() {
        String fullScript = "5102abcdabac"; // real codesep at byte index 4
        List<Integer> offsets = RunarContract.findCodesepOffsets(fullScript);
        assertEquals(List.of(4), offsets);
        int codeSepIdx = offsets.get(0);
        String subscript = fullScript.substring((codeSepIdx + 1) * 2);
        // Only the OP_CHECKSIG (ac) after the separator remains.
        assertEquals("ac", subscript);
    }

    @Test
    void returnsEmptyWhenNoCodesep() {
        assertEquals(List.of(),
            RunarContract.findCodesepOffsets("76a914" + "00".repeat(20) + "88ac"));
    }
}
