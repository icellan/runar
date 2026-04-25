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
 * Round-trip + canonical-shape tests for {@link Bsv21}. The expected
 * JSON shapes here must stay byte-identical to the Zig / TS / Ruby /
 * Go / Rust / Python SDKs.
 */
class Bsv21Test {

    private static final HexFormat HEX = HexFormat.of();

    private static String json(Inscription i) {
        return new String(HEX.parseHex(i.data()), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // Deploy genesis
    // ------------------------------------------------------------------

    @Test
    void deployEmitsCanonicalDeployMintShape() {
        Inscription i = Bsv21.deploy("RNR", 1_000_000L, null);
        assertEquals("application/bsv-20", i.contentType());
        // Genesis JSON: tokenId is computed from the deploy outpoint and
        // is intentionally NOT part of the inscription bytes — matches
        // Zig / TS / Ruby behaviour.
        assertEquals(
            "{\"p\":\"bsv-20\",\"op\":\"deploy+mint\",\"amt\":\"1000000\",\"sym\":\"RNR\"}",
            json(i)
        );
    }

    @Test
    void deployOmitsSymWhenEmpty() {
        Inscription i = Bsv21.deploy("", 500L, null);
        assertEquals(
            "{\"p\":\"bsv-20\",\"op\":\"deploy+mint\",\"amt\":\"500\"}",
            json(i)
        );
    }

    @Test
    void deployIgnoresTokenIdForByteOutput() {
        Inscription a = Bsv21.deploy("X", 10L, null);
        Inscription b = Bsv21.deploy("X", 10L, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_0");
        // tokenId argument MUST NOT change envelope bytes.
        assertEquals(a.data(), b.data());
        assertEquals(a.contentType(), b.contentType());
    }

    @Test
    void deployMintFullSignatureEmitsAllFields() {
        Inscription i = Bsv21.deployMint("1000000", "18", "RNR", "1a1b1c");
        assertEquals(
            "{\"p\":\"bsv-20\",\"op\":\"deploy+mint\",\"amt\":\"1000000\",\"dec\":\"18\",\"sym\":\"RNR\",\"icon\":\"1a1b1c\"}",
            json(i)
        );
    }

    // ------------------------------------------------------------------
    // Transfer
    // ------------------------------------------------------------------

    @Test
    void transferEmitsCanonicalShape() {
        String tokenId = "3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1";
        Inscription i = Bsv21.transfer(tokenId, 100L);
        assertEquals(
            "{\"p\":\"bsv-20\",\"op\":\"transfer\",\"id\":\"" + tokenId + "\",\"amt\":\"100\"}",
            json(i)
        );
    }

    // ------------------------------------------------------------------
    // Parse
    // ------------------------------------------------------------------

    @Test
    void parseRoundTripsDeploy() {
        Inscription i = Bsv21.deploy("RNR", 1_000_000L, null);
        Bsv21.Op op = Bsv21.parse(HEX.parseHex(i.data()));
        assertNotNull(op);
        assertEquals("bsv-20", op.p());
        assertEquals("deploy+mint", op.op());
        assertEquals("1000000", op.amt());
        assertEquals("RNR", op.sym());
        assertNull(op.id());
        assertNull(op.dec());
    }

    @Test
    void parseRoundTripsDeployMintFullShape() {
        Inscription i = Bsv21.deployMint("500", "8", "ABC", "deadbeef");
        Bsv21.Op op = Bsv21.parse(HEX.parseHex(i.data()));
        assertNotNull(op);
        assertEquals("deploy+mint", op.op());
        assertEquals("500", op.amt());
        assertEquals("8", op.dec());
        assertEquals("ABC", op.sym());
        assertEquals("deadbeef", op.icon());
    }

    @Test
    void parseRoundTripsTransfer() {
        String tokenId = "ab".repeat(32) + "_0";
        Inscription i = Bsv21.transfer(tokenId, 7L);
        Bsv21.Op op = Bsv21.parse(HEX.parseHex(i.data()));
        assertNotNull(op);
        assertEquals("transfer", op.op());
        assertEquals(tokenId, op.id());
        assertEquals("7", op.amt());
    }

    @Test
    void parseReturnsNullForBadInput() {
        assertNull(Bsv21.parse("{\"p\":\"foo\"}"));
        assertNull(Bsv21.parse(""));
        assertNull(Bsv21.parse(new byte[0]));
        assertNull(Bsv21.parse((byte[]) null));
    }

    // ------------------------------------------------------------------
    // Envelope reuse
    // ------------------------------------------------------------------

    @Test
    void inscriptionEnvelopeWraps() {
        Inscription i = Bsv21.transfer("aa".repeat(32) + "_0", 1L);
        String envelope = i.toEnvelopeHex();
        assertTrue(envelope.startsWith("006303" + "6f7264" + "51"), envelope);
        assertTrue(envelope.endsWith("68"), envelope);
    }
}
