package runar.lang.runtime;

import java.math.BigInteger;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.*;

class PreimageTest {

    @Test
    void defaultBuilderMatchesMockDefaults() {
        Preimage p = Preimage.builder().build();
        assertEquals(1L, p.version());
        assertEquals(0xfffffffeL, p.sequence());
        assertEquals(BigInteger.valueOf(10000), p.amount());
        assertEquals(0x41L, p.sighashType());
        assertEquals(0L, p.locktime());
    }

    @Test
    void extractorsMatchMockDefaults() {
        Preimage p = Preimage.builder().build();
        assertEquals(BigInteger.ONE, Preimage.extractVersion(p));
        assertEquals(BigInteger.valueOf(10000), Preimage.extractAmount(p));
        assertEquals(BigInteger.valueOf(0xfffffffeL), Preimage.extractSequence(p));
        assertEquals(BigInteger.valueOf(0x41), Preimage.extractSigHashType(p));
        assertEquals(BigInteger.ZERO, Preimage.extractLocktime(p));
        assertEquals(BigInteger.ZERO, Preimage.extractInputIndex(p));
        assertTrue(Preimage.checkPreimage(p));
    }

    @Test
    void builderRoundTripsViaSerialize() {
        byte[] hpr = new byte[32];
        byte[] hse = new byte[32];
        byte[] op = new byte[36];
        byte[] ho = new byte[32];
        for (int i = 0; i < 32; i++) { hpr[i] = (byte) (i + 1); hse[i] = (byte) (i + 40); ho[i] = (byte) (i + 70); }
        for (int i = 0; i < 36; i++) op[i] = (byte) (i + 100);

        Preimage before = Preimage.builder()
            .version(2L)
            .hashPrevouts(hpr)
            .hashSequence(hse)
            .outpoint(op)
            .scriptCode(new ByteString(new byte[] { 0x76, (byte) 0xa9, 0x14 }))
            .amount(BigInteger.valueOf(123456))
            .sequence(0x12345678L)
            .hashOutputs(ho)
            .locktime(999L)
            .sighashType(0x43L)
            .build();

        byte[] bytes = before.toBytes();
        Preimage after = Preimage.parse(bytes);

        assertEquals(before.version(), after.version());
        assertEquals(before.sequence(), after.sequence());
        assertEquals(before.amount(), after.amount());
        assertEquals(before.locktime(), after.locktime());
        assertEquals(before.sighashType(), after.sighashType());
        assertArrayEquals(before.hashPrevouts(), after.hashPrevouts());
        assertArrayEquals(before.hashSequence(), after.hashSequence());
        assertArrayEquals(before.outpoint(), after.outpoint());
        assertArrayEquals(before.hashOutputs(), after.hashOutputs());
        assertEquals(before.scriptCode().toHex(), after.scriptCode().toHex());
    }

    @Test
    void extractOutputHashEchoesFirst32Bytes() {
        byte[] hpr = new byte[32];
        for (int i = 0; i < 32; i++) hpr[i] = (byte) 0xaa;
        // extractOutputHash returns the first 32 bytes of the serialized preimage;
        // in BIP-143 format the first 32 bytes are: 4-byte version + 28 bytes of
        // hashPrevouts. With version=1 that's little-endian 01 00 00 00 || hpr[0..28].
        Preimage p = Preimage.builder().version(1L).hashPrevouts(hpr).build();
        byte[] raw = p.toBytes();
        byte[] expected = Arrays.copyOfRange(raw, 0, 32);
        assertEquals(bytesToHex(expected), Preimage.extractOutputHash(p).toHex());
    }

    @Test
    void hashOutputsFieldSetsExtractOutputs() {
        byte[] ho = new byte[32];
        for (int i = 0; i < 32; i++) ho[i] = (byte) 0x55;
        Preimage p = Preimage.builder().hashOutputs(ho).build();
        assertEquals(bytesToHex(ho), Preimage.extractOutputs(p).toHex());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
