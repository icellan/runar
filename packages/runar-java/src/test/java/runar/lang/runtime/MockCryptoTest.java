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

    /**
     * N-175: {@link MockCrypto}'s class javadoc said "Signature verification
     * is mocked (always returns success)" with no qualification, and never
     * named Rabin at all -- even though {@code verifyRabinSig} (below),
     * {@code verifyWOTS}, the six {@code verifySLHDSA_SHA2_*} methods, and
     * {@code verifyECDSA_P256}/{@code verifyECDSA_P384} all perform real
     * cryptography and reject a forged signature (see
     * {@code RabinPaddingBoundTest}, {@code wotsVerifyFailsOnTamperedMessage},
     * {@code SlhDsaTest}, {@code p256VerifyAcceptsBouncyCastleSignature}).
     *
     * <p>First, by execution: feed {@code verifyRabinSig} the universal-forgery
     * shape ({@code sig = 0}, {@code padding = SHA256(msg)}) that a verifier
     * which "always returns success" would accept, and confirm it is
     * rejected. Then read the class javadoc straight from the source file and
     * check it no longer makes the disproven blanket claim, does name Rabin
     * as real, and says what {@code checkSig} actually does (a null check,
     * not ECDSA math).
     *
     * <p>What this proves: the class-level javadoc text is consistent with
     * the executable behaviour of the methods it describes. What it does not
     * prove: the cryptographic correctness of any individual verifier (that
     * is {@code RabinPaddingBoundTest}'s, {@code SlhDsaTest}'s, etc. job) or
     * anything about the on-chain Script -- this is an off-chain simulator
     * doc, not a consensus claim.
     */
    @Test
    void classJavadocMatchesRealSignatureVerificationBehavior() throws java.io.IOException {
        // Real Rabin test primes (both ≡ 3 mod 4), mirroring RabinPaddingBoundTest.
        BigInteger p = new BigInteger("1361129467683753853853498429727072846227");
        BigInteger q = new BigInteger("1361129467683753853853498429727082846007");
        BigInteger n = p.multiply(q);
        byte[] msg = "N-175 javadoc fidelity check".getBytes();
        byte[] forgedPadding;
        try {
            forgedPadding = java.security.MessageDigest.getInstance("SHA-256").digest(msg);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        boolean accepted = MockCrypto.verifyRabinSig(
            new ByteString(msg), BigInteger.ZERO, new ByteString(forgedPadding), n);
        assertFalse(accepted,
            "verifyRabinSig accepted a forged signature -- if signature verification on "
            + "this class always returned success, this assertion would be backwards");

        String doc = classJavadoc();
        assertFalse(
            doc.contains("Signature verification is mocked (always returns success)"),
            "class javadoc still claims ALL signature verification always returns success, "
            + "which the forged-signature rejection above (and the existing WOTS+/SLH-DSA/"
            + "P-256/P-384 tests) disprove by execution");
        assertTrue(
            doc.toLowerCase(java.util.Locale.ROOT).contains("rabin"),
            "class javadoc never mentions Rabin, but verifyRabinSig performs real "
            + "verification -- the doc's list of real verifiers is incomplete");
        assertTrue(
            doc.contains("checkSig") && doc.toLowerCase(java.util.Locale.ROOT).contains("null"),
            "class javadoc does not say what checkSig actually does (a null check, not "
            + "ECDSA verification)");
    }

    /** Locates {@code MockCrypto.java}'s source whether tests run from the
     * {@code packages/runar-java} module root (Gradle's default) or the repo root. */
    private static java.nio.file.Path mockCryptoSourceFile() {
        java.nio.file.Path rel =
            java.nio.file.Path.of("src/main/java/runar/lang/runtime/MockCrypto.java");
        java.nio.file.Path here = java.nio.file.Path.of("").toAbsolutePath();
        if (java.nio.file.Files.exists(here.resolve(rel))) return here.resolve(rel);
        java.nio.file.Path nested = here.resolve("packages/runar-java").resolve(rel);
        if (java.nio.file.Files.exists(nested)) return nested;
        throw new IllegalStateException("cannot locate MockCrypto.java from " + here);
    }

    /** The class-level javadoc block immediately preceding {@code public final class MockCrypto}. */
    private static String classJavadoc() throws java.io.IOException {
        String src = java.nio.file.Files.readString(mockCryptoSourceFile());
        int classIdx = src.indexOf("public final class MockCrypto");
        assertTrue(classIdx > 0, "MockCrypto class declaration not found");
        int docEnd = src.lastIndexOf("*/", classIdx);
        int docStart = src.lastIndexOf("/**", docEnd);
        assertTrue(docStart >= 0 && docEnd > docStart, "class javadoc block not found");
        return src.substring(docStart, docEnd + 2);
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
        // `split` binds the RIGHT half, `left` the LEFT one -- the two sides of
        // the same cut. Asserting both is what makes this row able to fail: a
        // `split` that returned the left half would still be a plausible
        // single-valued function, and only the pair rules it out.
        assertEquals("0203", MockCrypto.split(a, BigInteger.ONE).toHex());
        assertEquals("01", MockCrypto.left(a, BigInteger.ONE).toHex());
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
    void ecOnCurveRejectsNonCanonicalX() {
        // CL-BUG-161 / F-243: coordinate canonicity. x0 = 1 is a genuine
        // secp256k1 curve point (y0 below). Point.fromRaw64 parses each half
        // as an unsigned BigInteger with no range check, so a coordinate
        // written as x0 + EC_P (still exactly 32 bytes) reaches the field
        // arithmetic in ecOnCurve, which reduces it mod EC_P and accepts it
        // as if it were x0. The compiled script range-checks x < p AND y < p
        // BEFORE the curve-equation check (GAP-301), so this mock must
        // reject what the script rejects. Verified against the real
        // compiled script via @bsv/sdk's Spend in
        // packages/runar-testing/src/__tests__/r117-coordinate-canonicity.test.ts
        // ("the predicate stays TOTAL: onCurve(alias) is false").
        BigInteger y0 = new BigInteger("4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee", 16);
        BigInteger ecP = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        BigInteger noncanonicalX = ecP.add(BigInteger.ONE);
        MockCrypto.Point aliasPoint = new MockCrypto.Point(noncanonicalX, y0);
        assertFalse(MockCrypto.ecOnCurve(aliasPoint));
    }

    @Test
    void ecOnCurveRejectsWrongWidthBytes() {
        // N-184: the compiled ecOnCurve is a PREDICATE over untrusted bytes --
        // for a 63- or 65-byte blob the script answers false, it does not
        // abort (emitPointLengthGate ANDs a width flag into the result; see
        // packages/runar-testing/src/__tests__/r052-point-length-gate.test.ts
        // "onCurve(G <plus> surplus) is FALSE, not true", executed on @bsv/sdk
        // Spend). MockCrypto.Point#fromRaw64 is the only bytes-to-Point path
        // and throws on the wrong width -- correct for ecAdd/ecMul/ecNegate,
        // which abort on the wrong width too -- so ecOnCurve needs a
        // byte-level overload that answers false instead of routing through
        // fromRaw64.
        byte[] g = HEX.parseHex(MockCrypto.EC_G.toHex());
        byte[] short63 = java.util.Arrays.copyOf(g, 63);
        byte[] long65 = java.util.Arrays.copyOf(g, 65);
        assertFalse(MockCrypto.ecOnCurve(short63));
        assertFalse(MockCrypto.ecOnCurve(long65));
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

    // --- SHA-256 compression / finalization -----------------------------

    @Test
    void sha256FinalizeOfAbcMatchesFipsVector() {
        // Single-block: "abc" → SHA-256 = ba7816bf...20015ad (FIPS 180-2 §B.1).
        ByteString out = MockCrypto.sha256Finalize(
            new ByteString(MockCrypto.SHA256_IV),
            new ByteString("abc".getBytes()),
            BigInteger.valueOf(24));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out.toHex());
    }

    @Test
    void sha256FinalizeOfEmptyMatchesFipsVector() {
        // SHA-256("") = e3b0c442...b7852b855
        ByteString out = MockCrypto.sha256Finalize(
            new ByteString(MockCrypto.SHA256_IV),
            new ByteString(new byte[0]),
            BigInteger.ZERO);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", out.toHex());
    }

    @Test
    void sha256FinalizeTwoBlockPath() {
        // 56-byte message — pad rolls into a second block (56 + 1 + 8 > 64).
        // FIPS 180-4 §B.2: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
        // 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        byte[] msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes();
        assertEquals(56, msg.length);
        ByteString out = MockCrypto.sha256Finalize(
            new ByteString(MockCrypto.SHA256_IV),
            new ByteString(msg),
            BigInteger.valueOf(msg.length * 8L));
        assertEquals("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", out.toHex());
    }

    @Test
    void sha256CompressMultiBlockEqualsBuiltinSha256() {
        // 119-byte message: 1 full compressed block + finalize-with-2-blocks path.
        byte[] msg = new byte[119];
        for (int i = 0; i < msg.length; i++) msg[i] = (byte) i;
        // Compress first 64 bytes via sha256Compress, then finalize with the
        // remaining 55 bytes — must match the JDK's SHA-256 over the whole
        // 119-byte input.
        ByteString first = MockCrypto.sha256Compress(
            new ByteString(MockCrypto.SHA256_IV),
            new ByteString(java.util.Arrays.copyOfRange(msg, 0, 64)));
        ByteString out = MockCrypto.sha256Finalize(
            first,
            new ByteString(java.util.Arrays.copyOfRange(msg, 64, 119)),
            BigInteger.valueOf(msg.length * 8L));
        assertEquals(HEX.formatHex(MockCrypto.sha256(msg)), out.toHex());
    }

    @Test
    void sha256CompressRejectsBadLengths() {
        assertThrows(IllegalArgumentException.class,
            () -> MockCrypto.sha256Compress(new ByteString(new byte[31]), new ByteString(new byte[64])));
        assertThrows(IllegalArgumentException.class,
            () -> MockCrypto.sha256Compress(new ByteString(new byte[32]), new ByteString(new byte[63])));
    }

    // --- Blake3 (cross-language pinned vectors from TS reference) -------

    @Test
    void blake3HashEmptyMatchesTsReference() {
        ByteString out = MockCrypto.blake3Hash(new ByteString(new byte[0]));
        assertEquals("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", out.toHex());
    }

    @Test
    void blake3HashAbcMatchesTsReference() {
        ByteString out = MockCrypto.blake3Hash(new ByteString("abc".getBytes()));
        assertEquals("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", out.toHex());
    }

    @Test
    void blake3HashHelloWorldMatchesTsReference() {
        ByteString out = MockCrypto.blake3Hash(new ByteString("hello world".getBytes()));
        assertEquals("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24", out.toHex());
    }

    @Test
    void blake3HashEqualsExplicitPaddedCompression() {
        // For a full 64-byte message, blake3Hash(msg) ≡ blake3Compress(IV, msg):
        // both use block_len=64. This identity only holds at exactly 64 bytes —
        // for shorter messages blake3Hash uses the real length as block_len
        // (standard BLAKE3), so it differs from the block_len=64 compression.
        byte[] msg = new byte[64];
        for (int i = 0; i < 64; i++) {
            msg[i] = (byte) i;
        }
        ByteString viaHash = MockCrypto.blake3Hash(new ByteString(msg));
        ByteString viaCompress = MockCrypto.blake3Compress(
            new ByteString(MockCrypto.BLAKE3_IV_BYTES),
            new ByteString(msg));
        assertEquals(viaCompress.toHex(), viaHash.toHex());
    }

    @Test
    void blake3HashRejectsMessagesLongerThan64BytesWithSharedDiagnostic() {
        // N-107: the on-chain blake3Hash script only ever handles a single 64-byte
        // block, so every off-chain tier must refuse >64 bytes with the SAME
        // diagnostic the TS reference interpreter throws (packages/runar-testing/
        // src/interpreter/interpreter.ts:1610) — matched verbatim (not just
        // "contains") across Go/Rust/Python/Ruby/TS so a caller parsing the message
        // doesn't see a tier-specific string. This proves the Java off-chain mock's
        // refusal text; it does not prove the on-chain script's behavior, Zig's
        // (untestable in-process) panic text, or any other tier.
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> MockCrypto.blake3Hash(new ByteString(new byte[65])));
        assertEquals("blake3Hash: message must be <= 64 bytes, got 65", ex.getMessage());
    }

    @Test
    void blake3CompressDeterministic() {
        ByteString out1 = MockCrypto.blake3Compress(
            new ByteString(MockCrypto.BLAKE3_IV_BYTES),
            new ByteString(new byte[64]));
        ByteString out2 = MockCrypto.blake3Compress(
            new ByteString(MockCrypto.BLAKE3_IV_BYTES),
            new ByteString(new byte[64]));
        assertEquals(out1.toHex(), out2.toHex());
        // Real impl: must not be all zeros (would indicate a stub).
        assertNotEquals("0000000000000000000000000000000000000000000000000000000000000000", out1.toHex());
    }

    @Test
    void blake3CompressRejectsBadLengths() {
        assertThrows(IllegalArgumentException.class,
            () -> MockCrypto.blake3Compress(new ByteString(new byte[31]), new ByteString(new byte[64])));
        assertThrows(IllegalArgumentException.class,
            () -> MockCrypto.blake3Compress(new ByteString(new byte[32]), new ByteString(new byte[63])));
    }

    // --- WOTS+ round-trip ----------------------------------------------

    @Test
    void wotsRoundTripSucceeds() {
        byte[] seed = "wots-test-seed-0001".getBytes();
        byte[] pubSeed = new byte[32];
        for (int i = 0; i < 32; i++) pubSeed[i] = (byte) i;
        byte[][] keys = MockCrypto.wotsKeygenDeterministic(seed, pubSeed);
        byte[] sk = keys[0];
        byte[] pk = keys[1];

        byte[] msg = "hello-runar-wots".getBytes();
        byte[] sig = MockCrypto.wotsSign(msg, sk, pubSeed);
        assertEquals(67 * 32, sig.length, "signature must be 67 × 32 = 2144 bytes");

        assertTrue(MockCrypto.verifyWOTS(new ByteString(msg), new ByteString(sig), new ByteString(pk)));
    }

    @Test
    void wotsVerifyFailsOnTamperedMessage() {
        byte[] seed = "wots-test-seed-0002".getBytes();
        byte[] pubSeed = new byte[32];
        for (int i = 0; i < 32; i++) pubSeed[i] = (byte) (i + 1);
        byte[][] keys = MockCrypto.wotsKeygenDeterministic(seed, pubSeed);

        byte[] msg = "approved-payment".getBytes();
        byte[] sig = MockCrypto.wotsSign(msg, keys[0], pubSeed);
        byte[] tampered = "approved-payment-NOT".getBytes();
        assertFalse(MockCrypto.verifyWOTS(new ByteString(tampered), new ByteString(sig), new ByteString(keys[1])));
    }

    @Test
    void wotsVerifyRejectsBadSignatureLength() {
        byte[] msg = "x".getBytes();
        byte[] badSig = new byte[100];
        byte[] pk = new byte[64];
        assertFalse(MockCrypto.verifyWOTS(new ByteString(msg), new ByteString(badSig), new ByteString(pk)));
    }

    @Test
    void wotsVerifyRejectsBadPubKeyLength() {
        byte[] msg = "x".getBytes();
        byte[] sig = new byte[67 * 32];
        byte[] badPk = new byte[63];
        assertFalse(MockCrypto.verifyWOTS(new ByteString(msg), new ByteString(sig), new ByteString(badPk)));
    }

    // --- NIST P-256 / P-384 ECDSA verification --------------------------

    @Test
    void p256VerifyAcceptsBouncyCastleSignature() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bcp = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC", bcp);
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), new java.security.SecureRandom("p256-fixed".getBytes()));
        java.security.KeyPair kp = kpg.generateKeyPair();

        byte[] msg = "p256 acceptance test".getBytes();
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA", bcp);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] derSig = signer.sign();

        byte[] rawSig = derToRaw(derSig, 32);
        byte[] compressedPk = ecPointCompress((java.security.interfaces.ECPublicKey) kp.getPublic(), 32);
        assertTrue(MockCrypto.verifyECDSA_P256(new ByteString(msg), new ByteString(rawSig), new ByteString(compressedPk)));

        byte[] tampered = "p256 acceptance test (modified)".getBytes();
        assertFalse(MockCrypto.verifyECDSA_P256(new ByteString(tampered), new ByteString(rawSig), new ByteString(compressedPk)));
    }

    @Test
    void p384VerifyAcceptsBouncyCastleSignature() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bcp = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC", bcp);
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"), new java.security.SecureRandom("p384-fixed".getBytes()));
        java.security.KeyPair kp = kpg.generateKeyPair();

        byte[] msg = "p384 acceptance test".getBytes();
        // On-chain codegen uses SHA-256 for both curves; mirror that here.
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA", bcp);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] derSig = signer.sign();

        byte[] rawSig = derToRaw(derSig, 48);
        byte[] compressedPk = ecPointCompress((java.security.interfaces.ECPublicKey) kp.getPublic(), 48);
        assertTrue(MockCrypto.verifyECDSA_P384(new ByteString(msg), new ByteString(rawSig), new ByteString(compressedPk)));
    }

    @Test
    void p256RejectsBadSignatureLength() {
        byte[] msg = "x".getBytes();
        byte[] badSig = new byte[63];
        byte[] pk = new byte[33];
        pk[0] = 0x02;
        assertFalse(MockCrypto.verifyECDSA_P256(new ByteString(msg), new ByteString(badSig), new ByteString(pk)));
    }

    @Test
    void p256RejectsZeroRorS() {
        byte[] msg = "x".getBytes();
        byte[] badSig = new byte[64]; // r=0, s=0
        byte[] pk = new byte[33];
        pk[0] = 0x02;
        for (int i = 1; i < 33; i++) pk[i] = (byte) i;
        assertFalse(MockCrypto.verifyECDSA_P256(new ByteString(msg), new ByteString(badSig), new ByteString(pk)));
    }

    /** Convert a DER-encoded ECDSA signature into raw r||s of fixed length. */
    private static byte[] derToRaw(byte[] der, int half) {
        // SEQUENCE { INTEGER r, INTEGER s }
        int i = 0;
        if (der[i++] != 0x30) throw new IllegalArgumentException("not a DER sequence");
        int seqLen = der[i++] & 0xff;
        if (der[i++] != 0x02) throw new IllegalArgumentException("expected INTEGER");
        int rLen = der[i++] & 0xff;
        byte[] r = java.util.Arrays.copyOfRange(der, i, i + rLen);
        i += rLen;
        if (der[i++] != 0x02) throw new IllegalArgumentException("expected INTEGER");
        int sLen = der[i++] & 0xff;
        byte[] s = java.util.Arrays.copyOfRange(der, i, i + sLen);

        byte[] out = new byte[2 * half];
        copyAlignedRight(r, out, 0, half);
        copyAlignedRight(s, out, half, half);
        return out;
    }

    private static void copyAlignedRight(byte[] src, byte[] dst, int dstOff, int width) {
        int skip = 0;
        // Strip leading sign-padding zero bytes if present.
        while (skip < src.length && src.length - skip > width && src[skip] == 0) skip++;
        int copyLen = src.length - skip;
        if (copyLen > width) throw new IllegalArgumentException("integer too wide for raw encoding");
        System.arraycopy(src, skip, dst, dstOff + (width - copyLen), copyLen);
    }

    /** Encode a JCE EC public key as compressed (1 + half bytes). */
    private static byte[] ecPointCompress(java.security.interfaces.ECPublicKey pub, int half) {
        byte[] x = pub.getW().getAffineX().toByteArray();
        byte[] y = pub.getW().getAffineY().toByteArray();
        byte[] out = new byte[1 + half];
        out[0] = (byte) ((y[y.length - 1] & 0x01) == 0 ? 0x02 : 0x03);
        // Right-align x into the last `half` bytes.
        int skip = 0;
        while (skip < x.length && x.length - skip > half && x[skip] == 0) skip++;
        int copyLen = x.length - skip;
        System.arraycopy(x, skip, out, 1 + (half - copyLen), copyLen);
        return out;
    }
}
