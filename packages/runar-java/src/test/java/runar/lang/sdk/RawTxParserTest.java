package runar.lang.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for {@link RawTxParser} against a well-known
 * Bitcoin transaction hex.
 */
class RawTxParserTest {

    /**
     * Parsed shape of the very first BSV / BTC P2PKH transaction
     * ever (Hal Finney to Satoshi). 1-input, 2-output, version 1,
     * locktime 0. Source: blockchain.com tx
     * f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16.
     */
    private static final String HAL_TX =
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847"
      + "30440220" + "4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104"
      + "ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
      + "00000000";

    @Test
    void parsesHalFinneyTransaction() {
        RawTx tx = RawTxParser.parse(HAL_TX);
        assertEquals(1, tx.version);
        assertEquals(1, tx.inputs.size());
        assertEquals(2, tx.outputs.size());
        assertEquals(0, tx.locktime);
        // Output 0 is 10 BTC; output 1 is the 40 BTC change back to Satoshi.
        assertEquals(10_00000000L, tx.outputs.get(0).satoshis);
        assertEquals(40_00000000L, tx.outputs.get(1).satoshis);
    }

    @Test
    void parsedTxRoundTripsToOriginalHex() {
        RawTx tx = RawTxParser.parse(HAL_TX);
        // Our serializer must produce byte-identical output for the same
        // canonical transaction shape.
        String roundTripped = tx.toHex();
        assertEquals(HAL_TX, roundTripped);
    }

    @Test
    void emptyOutputsRoundTrip() {
        // 1 input, 0 outputs, locktime 0.
        RawTx tx = new RawTx();
        tx.addInput("aa".repeat(32), 0, "");
        String hex = tx.toHex();
        RawTx parsed = RawTxParser.parse(hex);
        assertEquals(1, parsed.inputs.size());
        assertEquals(0, parsed.outputs.size());
    }

    @Test
    void varintEncodingHandlesAllWidthCategories() {
        // Test 1, 0xfd-0xffff, 0x10000-0xffffffff bounds via outputs.
        for (int n : new int[]{0, 1, 252, 253, 65_535, 65_536}) {
            RawTx tx = new RawTx();
            tx.addInput("aa".repeat(32), 0, "");
            for (int i = 0; i < n; i++) tx.addOutput(1L, "00");
            RawTx parsed = RawTxParser.parse(tx.toHex());
            assertEquals(n, parsed.outputs.size(), "n=" + n);
        }
    }
}
