package runar.lang.sdk;

import java.security.MessageDigest;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-checks for {@link OpPushTx}.
 *
 * <p>Round-trips a known transaction through {@link OpPushTx#preimage}
 * and verifies that {@code SHA256d(preimage)} matches the existing
 * {@link RawTx#sighashBIP143} machinery — i.e. the preimage bytes are
 * exactly the BIP-143 preimage the on-chain script would re-derive.
 *
 * <p>Also covers {@link OpPushTx#buildUnlock} push encoding and the
 * {@link OpPushTx#prepare} convenience round-trip.
 */
class OpPushTxTest {

    private static final HexFormat HEX = HexFormat.of();

    /**
     * Build a stable two-input / two-output transaction so the various
     * BIP-143 sub-hashes (hashPrevouts, hashSequence, hashOutputs) are
     * non-trivial — guards against collisions where one sub-hash being
     * accidentally zeroed wouldn't surface.
     */
    private static RawTx buildSampleTx() {
        RawTx tx = new RawTx();
        tx.version = 2;
        tx.locktime = 0;
        tx.addInput("ab".repeat(32), 0, "");
        tx.addInput("cd".repeat(32), 1, "");
        tx.inputs.get(1).sequence = 0xfffffffeL;
        tx.addOutput(7_000L, "76a914" + "11".repeat(20) + "88ac");
        tx.addOutput(2_500L, "76a914" + "22".repeat(20) + "88ac");
        return tx;
    }

    // ------------------------------------------------------------------
    // preimage(...) — bytes round-trip into the existing sighash machinery
    // ------------------------------------------------------------------

    @Test
    void preimageDoubleSha256MatchesRawTxSighash() throws Exception {
        RawTx tx = buildSampleTx();
        String subscriptHex = "76a914" + "33".repeat(20) + "88ac";
        long satoshis = 10_000L;
        int inputIndex = 0;

        byte[] preimage = OpPushTx.preimage(
            tx, inputIndex, ScriptUtils.hexToBytes(subscriptHex),
            satoshis, OpPushTx.SIGHASH_ALL_FORKID
        );

        // SHA256d(preimage) must equal the sighash from the canonical path.
        byte[] expectedSighash = tx.sighashBIP143(
            inputIndex, subscriptHex, satoshis, RawTx.SIGHASH_ALL_FORKID
        );
        byte[] actualSighash = sha256d(preimage);
        assertArrayEquals(expectedSighash, actualSighash,
            "SHA256d(preimage) must equal the BIP-143 sighash");
    }

    @Test
    void preimageWorksForSecondInput() throws Exception {
        RawTx tx = buildSampleTx();
        String subscriptHex = "76a914" + "44".repeat(20) + "88ac";
        long satoshis = 5_555L;
        int inputIndex = 1;

        byte[] preimage = OpPushTx.preimage(
            tx, inputIndex, ScriptUtils.hexToBytes(subscriptHex),
            satoshis, OpPushTx.SIGHASH_ALL_FORKID
        );
        byte[] expectedSighash = tx.sighashBIP143(
            inputIndex, subscriptHex, satoshis, RawTx.SIGHASH_ALL_FORKID
        );
        assertArrayEquals(expectedSighash, sha256d(preimage));
    }

    @Test
    void preimageStructureMatchesBIP143Layout() {
        RawTx tx = buildSampleTx();
        String subscriptHex = "ab"; // 1-byte script — exercises varint=1 path
        byte[] scriptCode = ScriptUtils.hexToBytes(subscriptHex);
        long satoshis = 12_345L;

        byte[] preimage = OpPushTx.preimage(
            tx, 0, scriptCode, satoshis, OpPushTx.SIGHASH_ALL_FORKID
        );

        // BIP-143 preimage layout, in order:
        //   4   version
        //  32   hashPrevouts
        //  32   hashSequence
        //  32   prev txid (LE)
        //   4   prev vout (LE)
        //  v    varint(scriptCode len) + scriptCode
        //   8   satoshis (LE)
        //   4   sequence
        //  32   hashOutputs
        //   4   locktime
        //   4   sighash flag
        // 4 + 32 + 32 + 32 + 4 + 1 (varint) + 1 (script) + 8 + 4 + 32 + 4 + 4 = 158
        assertEquals(158, preimage.length, "preimage length for 1-byte scriptCode");

        // version is 4 LE bytes of 2
        assertEquals(0x02, preimage[0]);
        assertEquals(0x00, preimage[1]);
        assertEquals(0x00, preimage[2]);
        assertEquals(0x00, preimage[3]);

        // last 4 bytes are sighash flag (0x41) LE
        assertEquals((byte) 0x41, preimage[preimage.length - 4]);
        assertEquals((byte) 0x00, preimage[preimage.length - 3]);
        assertEquals((byte) 0x00, preimage[preimage.length - 2]);
        assertEquals((byte) 0x00, preimage[preimage.length - 1]);
    }

    @Test
    void preimageRejectsOutOfRangeInputIndex() {
        RawTx tx = buildSampleTx();
        byte[] sc = new byte[] { 0x51 };
        assertThrows(IllegalArgumentException.class, () ->
            OpPushTx.preimage(tx, 5, sc, 1_000L, OpPushTx.SIGHASH_ALL_FORKID));
        assertThrows(IllegalArgumentException.class, () ->
            OpPushTx.preimage(tx, -1, sc, 1_000L, OpPushTx.SIGHASH_ALL_FORKID));
    }

    @Test
    void preimageRejectsNullArgs() {
        RawTx tx = buildSampleTx();
        assertThrows(IllegalArgumentException.class, () ->
            OpPushTx.preimage(null, 0, new byte[0], 1L, OpPushTx.SIGHASH_ALL_FORKID));
        assertThrows(IllegalArgumentException.class, () ->
            OpPushTx.preimage(tx, 0, null, 1L, OpPushTx.SIGHASH_ALL_FORKID));
    }

    // ------------------------------------------------------------------
    // buildUnlock(...) — push encoding + extras concatenation
    // ------------------------------------------------------------------

    @Test
    void buildUnlockEmitsMinimalPushdata1ForTypicalPreimage() {
        // 200-byte preimage → must use OP_PUSHDATA1 (0x4c)
        byte[] preimage = new byte[200];
        for (int i = 0; i < preimage.length; i++) preimage[i] = (byte) (i & 0xff);

        byte[] unlock = OpPushTx.buildUnlock(preimage);

        assertEquals(0x4c, unlock[0] & 0xff, "OP_PUSHDATA1");
        assertEquals(200, unlock[1] & 0xff, "length byte");
        // Body matches.
        for (int i = 0; i < preimage.length; i++) {
            assertEquals(preimage[i], unlock[2 + i], "body byte " + i);
        }
        assertEquals(2 + preimage.length, unlock.length);
    }

    @Test
    void buildUnlockConcatenatesExtrasInOrder() {
        byte[] preimage = new byte[150];
        for (int i = 0; i < preimage.length; i++) preimage[i] = (byte) i;
        byte[] extra1 = new byte[] { 0x01, 0x02, 0x03 };
        byte[] extra2 = new byte[] { (byte) 0xaa, (byte) 0xbb };

        byte[] unlock = OpPushTx.buildUnlock(preimage, extra1, extra2);

        // OP_PUSHDATA1 0x96 <preimage>
        assertEquals(0x4c, unlock[0] & 0xff);
        assertEquals(150,  unlock[1] & 0xff);
        // After the 152-byte preimage push:
        int p = 2 + 150;
        // extra1: 3-byte direct push (0x03 + 3 bytes)
        assertEquals(0x03, unlock[p] & 0xff);
        assertEquals(0x01, unlock[p + 1]);
        assertEquals(0x02, unlock[p + 2]);
        assertEquals(0x03, unlock[p + 3]);
        p += 4;
        // extra2: 2-byte direct push
        assertEquals(0x02, unlock[p] & 0xff);
        assertEquals((byte) 0xaa, unlock[p + 1]);
        assertEquals((byte) 0xbb, unlock[p + 2]);
        p += 3;
        assertEquals(p, unlock.length, "no trailing bytes");
    }

    @Test
    void buildUnlockUsesDirectPushForSmallPreimage() {
        byte[] preimage = new byte[] { 0x10, 0x20, 0x30 };
        byte[] unlock = OpPushTx.buildUnlock(preimage);
        // 3-byte preimage uses direct push 0x03 (not PUSHDATA1).
        assertEquals(0x03, unlock[0] & 0xff);
        assertEquals(0x10, unlock[1]);
        assertEquals(0x20, unlock[2]);
        assertEquals(0x30, unlock[3]);
        assertEquals(4, unlock.length);
    }

    @Test
    void buildUnlockRejectsNullPreimage() {
        assertThrows(IllegalArgumentException.class, () -> OpPushTx.buildUnlock(null));
    }

    @Test
    void buildUnlockRejectsNullExtra() {
        byte[] preimage = new byte[] { 0x01 };
        assertThrows(IllegalArgumentException.class, () ->
            OpPushTx.buildUnlock(preimage, new byte[] { 0x02 }, null));
    }

    // ------------------------------------------------------------------
    // prepare(...) — convenience round-trip
    // ------------------------------------------------------------------

    @Test
    void prepareReturnsPreimageAndSinglePushUnlockingScript() {
        RawTx tx = buildSampleTx();
        UTXO utxo = new UTXO("ab".repeat(32), 0, 10_000L,
            "76a914" + "55".repeat(20) + "88ac");

        OpPushTx.PushTxResult result = OpPushTx.prepare(
            tx, 0, utxo, OpPushTx.SIGHASH_ALL_FORKID
        );

        // The preimage matches the standalone preimage(...) call.
        byte[] direct = OpPushTx.preimage(
            tx, 0, ScriptUtils.hexToBytes(utxo.scriptHex()),
            utxo.satoshis(), OpPushTx.SIGHASH_ALL_FORKID
        );
        assertArrayEquals(direct, result.preimage());

        // The unlocking script's first push must equal the preimage bytes.
        // Decode using ScriptUtils so we're testing the same encoder used
        // by the rest of the SDK.
        String unlockHex = HEX.formatHex(result.unlockingScript());
        ScriptUtils.DecodedPush first = ScriptUtils.decodePushData(unlockHex, 0);
        assertEquals(HEX.formatHex(result.preimage()), first.dataHex());

        // No trailing bytes — prepare() pushes exactly one item.
        assertEquals(unlockHex.length(), first.hexCharsConsumed());
    }

    @Test
    void prepareRoundTripPreimageDoubleHashEqualsSighash() throws Exception {
        RawTx tx = buildSampleTx();
        UTXO utxo = new UTXO("ab".repeat(32), 0, 10_000L, "ab");

        OpPushTx.PushTxResult result = OpPushTx.prepare(
            tx, 0, utxo, OpPushTx.SIGHASH_ALL_FORKID
        );
        byte[] expected = tx.sighashBIP143(
            0, utxo.scriptHex(), utxo.satoshis(), RawTx.SIGHASH_ALL_FORKID
        );
        assertArrayEquals(expected, sha256d(result.preimage()));
    }

    @Test
    void prepareRejectsNullUtxo() {
        RawTx tx = buildSampleTx();
        assertThrows(IllegalArgumentException.class, () ->
            OpPushTx.prepare(tx, 0, null, OpPushTx.SIGHASH_ALL_FORKID));
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static byte[] sha256d(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(md.digest(data));
    }
}
