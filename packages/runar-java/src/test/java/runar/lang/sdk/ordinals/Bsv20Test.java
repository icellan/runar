package runar.lang.sdk.ordinals;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.Inscription;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trip + canonical-shape tests for {@link Bsv20}. The expected
 * JSON shapes here must stay byte-identical to the Zig / TS / Ruby /
 * Go / Rust / Python SDKs — diverging here would split the on-chain
 * envelope output across SDKs.
 */
class Bsv20Test {

    private static final HexFormat HEX = HexFormat.of();

    private static String json(Inscription i) {
        return new String(HEX.parseHex(i.data()), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // Deploy
    // ------------------------------------------------------------------

    @Test
    void deployEmitsCanonicalJsonShape() {
        Inscription i = Bsv20.deploy("RUNAR", 21_000_000L, 1000L, 0);

        assertEquals("application/bsv-20", i.contentType());
        assertEquals(
            "{\"p\":\"bsv-20\",\"op\":\"deploy\",\"tick\":\"RUNAR\",\"max\":\"21000000\",\"lim\":\"1000\",\"dec\":\"0\"}",
            json(i)
        );
    }

    @Test
    void deployOmitsLimWhenZero() {
        Inscription i = Bsv20.deploy("TEST", 1000L, 0L, -1);
        String j = json(i);
        assertTrue(j.contains("\"max\":\"1000\""), j);
        assertTrue(!j.contains("\"lim\""), j);
        assertTrue(!j.contains("\"dec\""), j);
    }

    @Test
    void deployStringOverloadOmitsOptionalsWhenNull() {
        Inscription i = Bsv20.deploy("TEST", "1000", null, null);
        assertEquals(
            "{\"p\":\"bsv-20\",\"op\":\"deploy\",\"tick\":\"TEST\",\"max\":\"1000\"}",
            json(i)
        );
    }

    // ------------------------------------------------------------------
    // Mint
    // ------------------------------------------------------------------

    @Test
    void mintEmitsCanonicalJsonShape() {
        Inscription i = Bsv20.mint("RUNAR", 1000L);
        assertEquals("application/bsv-20", i.contentType());
        assertEquals(
            "{\"p\":\"bsv-20\",\"op\":\"mint\",\"tick\":\"RUNAR\",\"amt\":\"1000\"}",
            json(i)
        );
    }

    // ------------------------------------------------------------------
    // Transfer
    // ------------------------------------------------------------------

    @Test
    void transferEmitsCanonicalJsonShape() {
        Inscription i = Bsv20.transfer("RUNAR", 50L);
        assertEquals(
            "{\"p\":\"bsv-20\",\"op\":\"transfer\",\"tick\":\"RUNAR\",\"amt\":\"50\"}",
            json(i)
        );
    }

    // ------------------------------------------------------------------
    // Parse
    // ------------------------------------------------------------------

    @Test
    void parseRoundTripsDeploy() {
        Inscription i = Bsv20.deploy("RUNAR", 21_000_000L, 1000L, 8);
        byte[] payload = HEX.parseHex(i.data());
        Bsv20.Op op = Bsv20.parse(payload);
        assertNotNull(op);
        assertEquals("bsv-20", op.p());
        assertEquals("deploy", op.op());
        assertEquals("RUNAR", op.tick());
        assertEquals("21000000", op.max());
        assertEquals("1000", op.lim());
        assertEquals("8", op.dec());
        assertNull(op.amt());
    }

    @Test
    void parseRoundTripsMint() {
        Inscription i = Bsv20.mint("ABC", 500L);
        Bsv20.Op op = Bsv20.parse(HEX.parseHex(i.data()));
        assertNotNull(op);
        assertEquals("mint", op.op());
        assertEquals("ABC", op.tick());
        assertEquals("500", op.amt());
    }

    @Test
    void parseRoundTripsTransfer() {
        Inscription i = Bsv20.transfer("ABC", 25L);
        Bsv20.Op op = Bsv20.parse(HEX.parseHex(i.data()));
        assertNotNull(op);
        assertEquals("transfer", op.op());
        assertEquals("ABC", op.tick());
        assertEquals("25", op.amt());
    }

    @Test
    void parseReturnsNullForNonBsv20Json() {
        assertNull(Bsv20.parse("{\"p\":\"ord\",\"op\":\"deploy\"}"));
    }

    @Test
    void parseReturnsNullForGarbage() {
        assertNull(Bsv20.parse("not json"));
        assertNull(Bsv20.parse(new byte[0]));
        assertNull(Bsv20.parse((byte[]) null));
    }

    // ------------------------------------------------------------------
    // Envelope reuse
    // ------------------------------------------------------------------

    @Test
    void inscriptionEnvelopeReusesExistingHelper() {
        Inscription i = Bsv20.mint("RUNAR", 1L);
        String envelope = i.toEnvelopeHex();
        // OP_FALSE OP_IF PUSH3 "ord" OP_1 ...
        assertTrue(envelope.startsWith("006303" + "6f7264" + "51"), envelope);
        // OP_ENDIF
        assertTrue(envelope.endsWith("68"), envelope);
        // Contains the content-type bytes (application/bsv-20 in hex)
        String ctHex = HEX.formatHex("application/bsv-20".getBytes(StandardCharsets.UTF_8));
        assertTrue(envelope.contains(ctHex), envelope);
    }
}
