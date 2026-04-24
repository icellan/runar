package runar.lang.runtime;

import java.math.BigInteger;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.*;

class MockCryptoTest {

    private static final HexFormat HEX = HexFormat.of();

    // --- Hashes against RFC test vectors -------------------------------

    @Test
    void sha256OfAbc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        byte[] result = MockCrypto.sha256("abc".getBytes());
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", HEX.formatHex(result));
    }

    @Test
    void sha256OfEmpty() {
        byte[] result = MockCrypto.sha256(new byte[0]);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", HEX.formatHex(result));
    }

    @Test
    void ripemd160OfAbc() {
        // RIPEMD-160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
        byte[] result = MockCrypto.ripemd160("abc".getBytes());
        assertEquals("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", HEX.formatHex(result));
    }

    @Test
    void ripemd160OfEmpty() {
        byte[] result = MockCrypto.ripemd160(new byte[0]);
        assertEquals("9c1185a5c5e9fc54612808977ee8f548b2258d31", HEX.formatHex(result));
    }

    @Test
    void hash160OfKnownPubkey() {
        // Known test vector: pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 (G)
        byte[] pk = HEX.parseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        byte[] result = MockCrypto.hash160(pk);
        // hash160 of the secp256k1 generator's compressed pubkey — stable test vector
        assertEquals("751e76e8199196d454941c45d1b3a323f1433bd6", HEX.formatHex(result));
    }

    @Test
    void hash256Double() {
        byte[] result = MockCrypto.hash256("abc".getBytes());
        // SHA-256(SHA-256("abc")) = 4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358
        assertEquals("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358", HEX.formatHex(result));
    }

    // --- ByteString-typed variants -------------------------------------

    @Test
    void sha256OverByteString() {
        ByteString h = MockCrypto.sha256(new ByteString("abc".getBytes()));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h.toHex());
    }

    @Test
    void hash160OverPubKey() {
        PubKey pk = PubKey.fromHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        Addr addr = MockCrypto.hash160(pk);
        assertEquals("751e76e8199196d454941c45d1b3a323f1433bd6", addr.toHex());
    }

    // --- Signature mocks -----------------------------------------------

    @Test
    void checkSigAlwaysTrueUnderSimulator() {
        Sig s = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
        PubKey pk = PubKey.fromHex("02" + "00".repeat(32));
        assertTrue(MockCrypto.checkSig(s, pk));
    }

    @Test
    void checkMultiSigAcceptsCorrectCounts() {
        Sig[] sigs = new Sig[] { Sig.fromHex("30"), Sig.fromHex("30") };
        PubKey[] pks = new PubKey[] { PubKey.fromHex("02" + "00".repeat(32)), PubKey.fromHex("03" + "00".repeat(32)), PubKey.fromHex("02" + "01".repeat(32)) };
        assertTrue(MockCrypto.checkMultiSig(sigs, pks));
    }

    @Test
    void checkMultiSigRejectsMoreSigsThanPubkeys() {
        Sig[] sigs = new Sig[] { Sig.fromHex("30"), Sig.fromHex("30") };
        PubKey[] pks = new PubKey[] { PubKey.fromHex("02" + "00".repeat(32)) };
        assertFalse(MockCrypto.checkMultiSig(sigs, pks));
    }

    // --- Math -----------------------------------------------------------

    @Test
    void mathBigIntegerOperations() {
        assertEquals(BigInteger.valueOf(7), MockCrypto.abs(BigInteger.valueOf(-7)));
        assertEquals(BigInteger.valueOf(3), MockCrypto.min(BigInteger.valueOf(3), BigInteger.valueOf(5)));
        assertEquals(BigInteger.valueOf(5), MockCrypto.max(BigInteger.valueOf(3), BigInteger.valueOf(5)));
        assertTrue(MockCrypto.within(BigInteger.valueOf(3), BigInteger.valueOf(0), BigInteger.valueOf(10)));
        assertFalse(MockCrypto.within(BigInteger.valueOf(10), BigInteger.valueOf(0), BigInteger.valueOf(10)));
        assertEquals(BigInteger.valueOf(1024), MockCrypto.pow(BigInteger.valueOf(2), BigInteger.valueOf(10)));
        assertEquals(BigInteger.valueOf(10), MockCrypto.log2(BigInteger.valueOf(1024)));
        assertEquals(BigInteger.valueOf(100), MockCrypto.sqrt(BigInteger.valueOf(10000)));
        assertEquals(BigInteger.valueOf(1), MockCrypto.sign(BigInteger.valueOf(5)));
        assertEquals(BigInteger.valueOf(-1), MockCrypto.sign(BigInteger.valueOf(-5)));
        assertEquals(BigInteger.valueOf(0), MockCrypto.sign(BigInteger.ZERO));
    }

    @Test
    void safeDivByZeroThrows() {
        assertThrows(ArithmeticException.class,
            () -> MockCrypto.safediv(BigInteger.TEN, BigInteger.ZERO));
    }

    // --- ByteString ops -------------------------------------------------

    @Test
    void byteStringOperations() {
        ByteString a = new ByteString(new byte[] { 0x01, 0x02, 0x03 });
        ByteString b = new ByteString(new byte[] { 0x04, 0x05 });
        assertEquals("0102030405", MockCrypto.cat(a, b).toHex());
        assertEquals(BigInteger.valueOf(3), MockCrypto.len(a));
        assertEquals("0203", MockCrypto.substr(a, BigInteger.ONE, BigInteger.TWO).toHex());
        assertEquals("030201", MockCrypto.reverseBytes(a).toHex());
        assertEquals("01", MockCrypto.left(a, BigInteger.ONE).toHex());
        assertEquals("03", MockCrypto.right(a, BigInteger.ONE).toHex());
        ByteString[] parts = MockCrypto.split(a, BigInteger.ONE);
        assertEquals("01", parts[0].toHex());
        assertEquals("0203", parts[1].toHex());
    }

    @Test
    void num2binAndBin2num() {
        ByteString enc = MockCrypto.num2bin(BigInteger.valueOf(0x1234), BigInteger.valueOf(4));
        // little-endian, padded to 4 bytes
        assertEquals("34120000", enc.toHex());
        BigInteger decoded = MockCrypto.bin2num(enc);
        assertEquals(BigInteger.valueOf(0x1234), decoded);
    }

    @Test
    void num2binRoundTripZero() {
        ByteString z = MockCrypto.num2bin(BigInteger.ZERO, BigInteger.valueOf(4));
        assertEquals("00000000", z.toHex());
        assertEquals(BigInteger.ZERO, MockCrypto.bin2num(z));
    }

    @Test
    void num2binRoundTripNegative() {
        // Bitcoin script encoding: low byte LE, high bit = sign.
        ByteString n = MockCrypto.num2bin(BigInteger.valueOf(-5), BigInteger.valueOf(2));
        // 5 = 0x05; with negative sign bit moved to padded MSB: 0x05 0x80
        assertEquals("0580", n.toHex());
        assertEquals(BigInteger.valueOf(-5), MockCrypto.bin2num(n));
    }

    // --- EC operations (secp256k1) -------------------------------------

    @Test
    void ecMulGenByOneIsG() {
        MockCrypto.Point g = MockCrypto.ecMulGen(BigInteger.ONE);
        assertEquals(MockCrypto.EC_G, g);
    }

    @Test
    void ecDoubleIsAddToSelf() {
        MockCrypto.Point g2a = MockCrypto.ecAdd(MockCrypto.EC_G, MockCrypto.EC_G);
        MockCrypto.Point g2b = MockCrypto.ecMulGen(BigInteger.TWO);
        assertEquals(g2a, g2b);
    }

    @Test
    void ecMulByNIsInfinity() {
        // k = N should yield infinity (group order).
        MockCrypto.Point p = MockCrypto.ecMulGen(MockCrypto.EC_N);
        assertTrue(p.infinity);
    }

    @Test
    void ecOnCurveHoldsForG() {
        assertTrue(MockCrypto.ecOnCurve(MockCrypto.EC_G));
    }

    @Test
    void ecNegateRoundTrip() {
        MockCrypto.Point negG = MockCrypto.ecNegate(MockCrypto.EC_G);
        MockCrypto.Point sum = MockCrypto.ecAdd(MockCrypto.EC_G, negG);
        assertTrue(sum.infinity);
    }

    @Test
    void ecEncodeCompressedShape() {
        ByteString enc = MockCrypto.ecEncodeCompressed(MockCrypto.EC_G);
        assertEquals(33, enc.length());
        String hex = enc.toHex();
        assertTrue(hex.startsWith("02") || hex.startsWith("03"), "prefix should be 02 or 03, got " + hex.substring(0, 2));
    }

    @Test
    void ecPointXAndY() {
        assertEquals(MockCrypto.EC_G.x, MockCrypto.ecPointX(MockCrypto.EC_G));
        assertEquals(MockCrypto.EC_G.y, MockCrypto.ecPointY(MockCrypto.EC_G));
    }

    // --- Field arithmetic ----------------------------------------------

    @Test
    void babyBearFieldBasics() {
        BigInteger sum = MockCrypto.bbFieldAdd(BigInteger.valueOf(1), BigInteger.valueOf(2));
        assertEquals(BigInteger.valueOf(3), sum);
        BigInteger prod = MockCrypto.bbFieldMul(BigInteger.valueOf(2), BigInteger.valueOf(3));
        assertEquals(BigInteger.valueOf(6), prod);
    }

    // --- Merkle --------------------------------------------------------

    @Test
    void merkleRootSha256SingleStep() {
        byte[] leafBytes = new byte[32];
        byte[] siblingBytes = new byte[32];
        for (int i = 0; i < 32; i++) siblingBytes[i] = (byte) 1;
        ByteString leaf = new ByteString(leafBytes);
        ByteString proof = new ByteString(siblingBytes);
        ByteString root = MockCrypto.merkleRootSha256(leaf, proof, BigInteger.ZERO, BigInteger.ONE);
        // index 0 ⇒ current||sibling (left); equals sha256(zeros || ones)
        byte[] concat = new byte[64];
        for (int i = 32; i < 64; i++) concat[i] = 1;
        assertEquals(HEX.formatHex(MockCrypto.sha256(concat)), root.toHex());
    }
}
