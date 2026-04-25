package runar.lang.runtime;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

/**
 * Off-chain simulator implementations for every Rúnar builtin.
 *
 * <p>Mirrors {@code packages/runar-lang/src/runtime/builtins.ts} in the
 * TypeScript reference runtime. Hash functions use real
 * {@link MessageDigest} implementations (SHA-256 via JDK, RIPEMD-160 via
 * BouncyCastle when available, falling back to a pure-Java port otherwise).
 * Signature verification is mocked (always returns success) since genuine
 * verification would require a full Bitcoin transaction context; that is
 * the Script VM's job, not the simulator's.
 *
 * <p>Math and ByteString operations are real. EC operations use
 * BouncyCastle's secp256k1 curve if the BC provider is on the classpath.
 * Post-quantum verifications (WOTS, SLH-DSA SHA-2 variants), Blake3,
 * NIST P-256 / P-384 ECDSA verification, and SHA-256 partial compression
 * (sha256Compress / sha256Finalize) are real implementations.
 *
 * <p>BabyBear and KoalaBear field arithmetic remain real (small primes,
 * trivial BigInteger ports). BN254 and Poseidon2 are intentionally Go-only
 * (proof-system primitives) and throw {@link UnsupportedOperationException};
 * test contracts that exercise them via the compiler+VM path.
 */
public final class MockCrypto {

    private MockCrypto() {}

    private static final HexFormat HEX = HexFormat.of();

    // =======================================================================
    // Hash functions — real
    // =======================================================================

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public static byte[] hash256(byte[] data) {
        return sha256(sha256(data));
    }

    public static byte[] ripemd160(byte[] data) {
        // Prefer BouncyCastle if present (testImplementation); else use the
        // pure-Java fallback so the production jar doesn't require BC.
        try {
            MessageDigest md = MessageDigest.getInstance("RIPEMD160");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            return Ripemd160.digest(data);
        }
    }

    public static byte[] hash160(byte[] data) {
        return ripemd160(sha256(data));
    }

    /** Convenience: hash160 over a PubKey returning Addr. */
    public static Addr hash160(PubKey pubKey) {
        return new Addr(hash160(pubKey.toByteArray()));
    }

    /** Convenience: hash160 over any ByteString returning an Addr-shaped result. */
    public static Addr hash160(ByteString bs) {
        return new Addr(hash160(bs.toByteArray()));
    }

    public static ByteString sha256(ByteString bs) {
        return new ByteString(sha256(bs.toByteArray()));
    }

    public static ByteString ripemd160(ByteString bs) {
        return new ByteString(ripemd160(bs.toByteArray()));
    }

    public static ByteString hash256(ByteString bs) {
        return new ByteString(hash256(bs.toByteArray()));
    }

    // =======================================================================
    // Signature verification — mocked
    // =======================================================================

    /**
     * Always returns true in simulator mode. Real ECDSA verification is
     * the Bitcoin Script VM's responsibility. Contracts that want to
     * test the equality branch of a "sig + pubkey" check should assert
     * on hash equality (which is real), not on checkSig.
     */
    public static boolean checkSig(Sig sig, PubKey pubKey) {
        return sig != null && pubKey != null;
    }

    /**
     * Accepts up to N sigs for N pubkeys; rejects only if more sigs
     * than pubkeys were supplied.
     */
    public static boolean checkMultiSig(Sig[] sigs, PubKey[] pubKeys) {
        return sigs != null && pubKeys != null && sigs.length <= pubKeys.length;
    }

    public static boolean verifyRabinSig(ByteString msg, BigInteger sig, ByteString padding, BigInteger pubKey) {
        return true;
    }

    /**
     * WOTS+ (Winternitz One-Time Signature) verification, RFC 8391
     * compatible with tweakable hash {@code F(pubSeed, ADRS, M)}.
     * Parameters: w=16, n=32 (SHA-256), len=67. Signature: 67 × 32 = 2144
     * bytes. Public key: 64 bytes (pubSeed‖pkRoot).
     *
     * <p>Mirrors {@code packages/runar-py/runar/wots.py:wots_verify} and
     * the Go reference at {@code packages/runar-go/wots.go}.
     */
    public static boolean verifyWOTS(ByteString msg, ByteString sig, ByteString pubKey) {
        byte[] msgBytes = msg.toByteArray();
        byte[] sigBytes = sig.toByteArray();
        byte[] pkBytes = pubKey.toByteArray();
        if (sigBytes.length != WOTS_LEN * WOTS_N) return false;
        if (pkBytes.length != 2 * WOTS_N) return false;

        byte[] pubSeed = Arrays.copyOfRange(pkBytes, 0, WOTS_N);
        byte[] pkRoot = Arrays.copyOfRange(pkBytes, WOTS_N, 2 * WOTS_N);

        byte[] msgHash = sha256(msgBytes);
        int[] digits = wotsAllDigits(msgHash);

        byte[] endpoints = new byte[WOTS_LEN * WOTS_N];
        for (int i = 0; i < WOTS_LEN; i++) {
            byte[] sigElement = Arrays.copyOfRange(sigBytes, i * WOTS_N, (i + 1) * WOTS_N);
            int remaining = (WOTS_W - 1) - digits[i];
            byte[] endpoint = wotsChain(sigElement, digits[i], remaining, pubSeed, i);
            System.arraycopy(endpoint, 0, endpoints, i * WOTS_N, WOTS_N);
        }

        byte[] computedRoot = sha256(endpoints);
        return Arrays.equals(computedRoot, pkRoot);
    }

    private static final int WOTS_W = 16;
    private static final int WOTS_N = 32;
    private static final int WOTS_LEN1 = 64; // ceil(8*N / log2(W))
    private static final int WOTS_LEN2 = 3;  // floor(log2(LEN1*(W-1))/log2(W)) + 1
    private static final int WOTS_LEN = WOTS_LEN1 + WOTS_LEN2; // 67

    private static byte[] wotsF(byte[] pubSeed, int chainIdx, int stepIdx, byte[] msg) {
        byte[] in = new byte[pubSeed.length + 2 + msg.length];
        System.arraycopy(pubSeed, 0, in, 0, pubSeed.length);
        in[pubSeed.length] = (byte) chainIdx;
        in[pubSeed.length + 1] = (byte) stepIdx;
        System.arraycopy(msg, 0, in, pubSeed.length + 2, msg.length);
        return sha256(in);
    }

    private static byte[] wotsChain(byte[] x, int startStep, int steps, byte[] pubSeed, int chainIdx) {
        byte[] current = x;
        for (int j = startStep; j < startStep + steps; j++) {
            current = wotsF(pubSeed, chainIdx, j, current);
        }
        return current;
    }

    /**
     * WOTS+ keypair generation. Test-only helper that mirrors
     * {@code packages/runar-py/runar/wots.py:wots_keygen}. Production
     * contracts only need {@link #verifyWOTS}; this exists so tests can
     * round-trip sign/verify without an external reference implementation.
     */
    public static byte[][] wotsKeygenDeterministic(byte[] seed, byte[] pubSeed) {
        if (pubSeed.length != WOTS_N) throw new IllegalArgumentException("pubSeed must be 32 bytes");
        byte[][] sk = new byte[WOTS_LEN][];
        for (int i = 0; i < WOTS_LEN; i++) {
            byte[] buf = new byte[seed.length + 4];
            System.arraycopy(seed, 0, buf, 0, seed.length);
            buf[seed.length]     = (byte) (i >>> 24);
            buf[seed.length + 1] = (byte) (i >>> 16);
            buf[seed.length + 2] = (byte) (i >>> 8);
            buf[seed.length + 3] = (byte) i;
            sk[i] = sha256(buf);
        }
        byte[] endpoints = new byte[WOTS_LEN * WOTS_N];
        for (int i = 0; i < WOTS_LEN; i++) {
            byte[] endpoint = wotsChain(sk[i], 0, WOTS_W - 1, pubSeed, i);
            System.arraycopy(endpoint, 0, endpoints, i * WOTS_N, WOTS_N);
        }
        byte[] pkRoot = sha256(endpoints);
        byte[] pk = new byte[2 * WOTS_N];
        System.arraycopy(pubSeed, 0, pk, 0, WOTS_N);
        System.arraycopy(pkRoot, 0, pk, WOTS_N, WOTS_N);
        // Pack secret key elements into a contiguous buffer for return.
        byte[] skFlat = new byte[WOTS_LEN * WOTS_N];
        for (int i = 0; i < WOTS_LEN; i++) System.arraycopy(sk[i], 0, skFlat, i * WOTS_N, WOTS_N);
        return new byte[][]{ skFlat, pk };
    }

    /** WOTS+ signing helper for tests. {@code skFlat} is 67 × 32 = 2144 bytes. */
    public static byte[] wotsSign(byte[] msg, byte[] skFlat, byte[] pubSeed) {
        if (skFlat.length != WOTS_LEN * WOTS_N) throw new IllegalArgumentException("sk must be 2144 bytes");
        byte[] msgHash = sha256(msg);
        int[] digits = wotsAllDigits(msgHash);
        byte[] sig = new byte[WOTS_LEN * WOTS_N];
        for (int i = 0; i < WOTS_LEN; i++) {
            byte[] skElem = Arrays.copyOfRange(skFlat, i * WOTS_N, (i + 1) * WOTS_N);
            byte[] elem = wotsChain(skElem, 0, digits[i], pubSeed, i);
            System.arraycopy(elem, 0, sig, i * WOTS_N, WOTS_N);
        }
        return sig;
    }

    private static int[] wotsAllDigits(byte[] msgHash) {
        int[] digits = new int[WOTS_LEN];
        for (int i = 0; i < WOTS_LEN1 / 2; i++) {
            int b = msgHash[i] & 0xff;
            digits[2 * i] = (b >>> 4) & 0x0f;
            digits[2 * i + 1] = b & 0x0f;
        }
        // Checksum (FIPS 8391 §3.5)
        int total = 0;
        for (int i = 0; i < WOTS_LEN1; i++) total += (WOTS_W - 1) - digits[i];
        int remaining = total;
        for (int i = WOTS_LEN2 - 1; i >= 0; i--) {
            digits[WOTS_LEN1 + i] = remaining % WOTS_W;
            remaining /= WOTS_W;
        }
        return digits;
    }

    public static boolean verifySLHDSA_SHA2_128s(ByteString msg, ByteString sig, ByteString pubKey) {
        return SlhDsa.verify(SlhDsa.SHA2_128s, msg.toByteArray(), sig.toByteArray(), pubKey.toByteArray());
    }
    public static boolean verifySLHDSA_SHA2_128f(ByteString msg, ByteString sig, ByteString pubKey) {
        return SlhDsa.verify(SlhDsa.SHA2_128f, msg.toByteArray(), sig.toByteArray(), pubKey.toByteArray());
    }
    public static boolean verifySLHDSA_SHA2_192s(ByteString msg, ByteString sig, ByteString pubKey) {
        return SlhDsa.verify(SlhDsa.SHA2_192s, msg.toByteArray(), sig.toByteArray(), pubKey.toByteArray());
    }
    public static boolean verifySLHDSA_SHA2_192f(ByteString msg, ByteString sig, ByteString pubKey) {
        return SlhDsa.verify(SlhDsa.SHA2_192f, msg.toByteArray(), sig.toByteArray(), pubKey.toByteArray());
    }
    public static boolean verifySLHDSA_SHA2_256s(ByteString msg, ByteString sig, ByteString pubKey) {
        return SlhDsa.verify(SlhDsa.SHA2_256s, msg.toByteArray(), sig.toByteArray(), pubKey.toByteArray());
    }
    public static boolean verifySLHDSA_SHA2_256f(ByteString msg, ByteString sig, ByteString pubKey) {
        return SlhDsa.verify(SlhDsa.SHA2_256f, msg.toByteArray(), sig.toByteArray(), pubKey.toByteArray());
    }

    /**
     * NIST P-256 ECDSA verification. Mirrors the on-chain codegen and the
     * Python reference at {@code packages/runar-py/runar/builtins.py:verify_ecdsa_p256}.
     *
     * @param msg raw message (hashed internally with SHA-256).
     * @param sig 64-byte raw signature: r[32] ‖ s[32] (big-endian).
     * @param pk  33-byte compressed P-256 public key (0x02/0x03 prefix + x[32]).
     */
    public static boolean verifyECDSA_P256(ByteString msg, ByteString sig, ByteString pk) {
        return verifyNistEcdsa(msg.toByteArray(), sig.toByteArray(), pk.toByteArray(), P256_PARAMS);
    }

    /**
     * NIST P-384 ECDSA verification. Note: matches the on-chain codegen
     * which hashes with SHA-256 (not SHA-384) for both P-256 and P-384 —
     * this is intentional for Bitcoin Script compatibility.
     *
     * @param msg raw message (hashed internally with SHA-256).
     * @param sig 96-byte raw signature: r[48] ‖ s[48] (big-endian).
     * @param pk  49-byte compressed P-384 public key (0x02/0x03 prefix + x[48]).
     */
    public static boolean verifyECDSA_P384(ByteString msg, ByteString sig, ByteString pk) {
        return verifyNistEcdsa(msg.toByteArray(), sig.toByteArray(), pk.toByteArray(), P384_PARAMS);
    }

    private static final class NistCurve {
        final BigInteger p, n, a, b, gx, gy;
        final int byteLen;
        NistCurve(BigInteger p, BigInteger n, BigInteger a, BigInteger b,
                  BigInteger gx, BigInteger gy, int byteLen) {
            this.p = p; this.n = n; this.a = a; this.b = b;
            this.gx = gx; this.gy = gy; this.byteLen = byteLen;
        }
    }

    private static final NistCurve P256_PARAMS = new NistCurve(
        new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16),
        new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
        BigInteger.valueOf(-3),
        new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16),
        new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
        new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16),
        32);

    private static final NistCurve P384_PARAMS = new NistCurve(
        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16),
        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
        BigInteger.valueOf(-3),
        new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16),
        new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16),
        new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16),
        48);

    private static boolean verifyNistEcdsa(byte[] msg, byte[] sig, byte[] pk, NistCurve c) {
        if (sig.length != 2 * c.byteLen) return false;
        if (pk.length != 1 + c.byteLen) return false;
        int prefix = pk[0] & 0xff;
        if (prefix != 0x02 && prefix != 0x03) return false;

        BigInteger pkx = new BigInteger(1, Arrays.copyOfRange(pk, 1, pk.length));
        BigInteger A = mod(c.a, c.p);
        BigInteger y2 = mod(pkx.modPow(BigInteger.valueOf(3), c.p)
                .add(A.multiply(pkx)).add(c.b), c.p);
        BigInteger y = y2.modPow(c.p.add(BigInteger.ONE).shiftRight(2), c.p);
        if (!y.modPow(BigInteger.TWO, c.p).equals(y2)) return false;
        if ((y.testBit(0) ? 1 : 0) != (prefix & 1)) y = c.p.subtract(y);

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, c.byteLen));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, c.byteLen, 2 * c.byteLen));
        if (r.signum() <= 0 || s.signum() <= 0 || r.compareTo(c.n) >= 0 || s.compareTo(c.n) >= 0) return false;

        BigInteger z = new BigInteger(1, sha256(msg));
        BigInteger w = s.modInverse(c.n);
        BigInteger u1 = z.multiply(w).mod(c.n);
        BigInteger u2 = r.multiply(w).mod(c.n);

        BigInteger[] gxgy = nistMul(c.gx, c.gy, u1, c);
        BigInteger[] qxqy = nistMul(pkx, y, u2, c);
        BigInteger[] sum = nistAdd(gxgy[0], gxgy[1], qxqy[0], qxqy[1], c);
        if (sum[0] == null) return false;
        return sum[0].mod(c.n).equals(r);
    }

    private static BigInteger[] nistAdd(BigInteger x1, BigInteger y1, BigInteger x2, BigInteger y2, NistCurve c) {
        if (x1 == null) return new BigInteger[]{ x2, y2 };
        if (x2 == null) return new BigInteger[]{ x1, y1 };
        BigInteger lam;
        if (x1.equals(x2)) {
            if (!y1.equals(y2)) return new BigInteger[]{ null, null };
            BigInteger num = BigInteger.valueOf(3).multiply(x1).multiply(x1).add(c.a);
            lam = num.multiply(BigInteger.TWO.multiply(y1).modInverse(c.p)).mod(c.p);
        } else {
            lam = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(c.p)).mod(c.p);
        }
        BigInteger x3 = lam.multiply(lam).subtract(x1).subtract(x2).mod(c.p);
        BigInteger y3 = lam.multiply(x1.subtract(x3)).subtract(y1).mod(c.p);
        return new BigInteger[]{ x3, y3 };
    }

    private static BigInteger[] nistMul(BigInteger x, BigInteger y, BigInteger k, NistCurve c) {
        BigInteger rx = null, ry = null;
        BigInteger qx = x, qy = y;
        BigInteger scalar = k;
        while (scalar.signum() > 0) {
            if (scalar.testBit(0)) {
                BigInteger[] sum = nistAdd(rx, ry, qx, qy, c);
                rx = sum[0]; ry = sum[1];
            }
            BigInteger[] dbl = nistAdd(qx, qy, qx, qy, c);
            qx = dbl[0]; qy = dbl[1];
            scalar = scalar.shiftRight(1);
        }
        return new BigInteger[]{ rx, ry };
    }

    // BLAKE3 single-block compression. Mirrors the on-chain codegen
    // (blockLen=64, counter=0, flags=11 = CHUNK_START | CHUNK_END | ROOT).
    // This covers all single-block uses exercised by Rúnar contracts; the
    // emitted Script can't express multi-block Blake3, so no multi-block
    // path is needed.

    private static final int[] BLAKE3_IV = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    /** 32-byte big-endian Blake3 IV bytes (compiler-side chaining-value seed). */
    public static final byte[] BLAKE3_IV_BYTES = blake3IvBytes();

    private static byte[] blake3IvBytes() {
        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) packBE32(out, i * 4, BLAKE3_IV[i]);
        return out;
    }

    private static final int[] BLAKE3_MSG_PERM = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

    private static void blake3G(int[] s, int a, int b, int c, int d, int mx, int my) {
        s[a] = s[a] + s[b] + mx;
        s[d] = rotr32(s[d] ^ s[a], 16);
        s[c] = s[c] + s[d];
        s[b] = rotr32(s[b] ^ s[c], 12);
        s[a] = s[a] + s[b] + my;
        s[d] = rotr32(s[d] ^ s[a], 8);
        s[c] = s[c] + s[d];
        s[b] = rotr32(s[b] ^ s[c], 7);
    }

    private static void blake3Round(int[] s, int[] m) {
        blake3G(s, 0, 4, 8, 12, m[0], m[1]);
        blake3G(s, 1, 5, 9, 13, m[2], m[3]);
        blake3G(s, 2, 6, 10, 14, m[4], m[5]);
        blake3G(s, 3, 7, 11, 15, m[6], m[7]);
        blake3G(s, 0, 5, 10, 15, m[8], m[9]);
        blake3G(s, 1, 6, 11, 12, m[10], m[11]);
        blake3G(s, 2, 7, 8, 13, m[12], m[13]);
        blake3G(s, 3, 4, 9, 14, m[14], m[15]);
    }

    /**
     * BLAKE3 single-block compression with blockLen=64, counter=0,
     * flags=11 (CHUNK_START | CHUNK_END | ROOT). Matches the on-chain
     * codegen at {@code compilers/java/src/main/java/runar/compiler/codegen/Blake3.java}
     * and the Python reference at {@code packages/runar-py/runar/builtins.py:_blake3_compress_impl}.
     *
     * @param state 32-byte chaining value (8 big-endian uint32s).
     * @param block 64-byte input block.
     */
    public static ByteString blake3Compress(ByteString state, ByteString block) {
        byte[] cv = state.toByteArray();
        byte[] blk = block.toByteArray();
        if (cv.length != 32) throw new IllegalArgumentException("blake3Compress: state must be 32 bytes, got " + cv.length);
        if (blk.length != 64) throw new IllegalArgumentException("blake3Compress: block must be 64 bytes, got " + blk.length);

        int[] h = new int[8];
        for (int i = 0; i < 8; i++) h[i] = unpackBE32(cv, i * 4);
        int[] m = new int[16];
        for (int i = 0; i < 16; i++) m[i] = unpackBE32(blk, i * 4);

        int[] s = new int[]{
            h[0], h[1], h[2], h[3],
            h[4], h[5], h[6], h[7],
            BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
            0, 0, 64, 11,
        };

        int[] msg = m.clone();
        for (int r = 0; r < 7; r++) {
            blake3Round(s, msg);
            if (r < 6) {
                int[] permuted = new int[16];
                for (int i = 0; i < 16; i++) permuted[i] = msg[BLAKE3_MSG_PERM[i]];
                msg = permuted;
            }
        }

        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) packBE32(out, i * 4, s[i] ^ s[i + 8]);
        return new ByteString(out);
    }

    /**
     * Single-block Blake3 hash for messages up to 64 bytes. Pads with
     * zero bytes and feeds the IV as the chaining value, matching the
     * compiler codegen and the TS interpreter reference.
     */
    public static ByteString blake3Hash(ByteString data) {
        byte[] msg = data.toByteArray();
        if (msg.length > 64) {
            throw new IllegalArgumentException("blake3Hash: simulator supports messages ≤ 64 bytes, got " + msg.length);
        }
        byte[] padded = new byte[64];
        System.arraycopy(msg, 0, padded, 0, msg.length);
        return blake3Compress(new ByteString(BLAKE3_IV_BYTES), new ByteString(padded));
    }

    // =======================================================================
    // Math — real BigInteger implementations
    // =======================================================================

    public static BigInteger abs(BigInteger x) { return x.abs(); }
    public static BigInteger min(BigInteger a, BigInteger b) { return a.compareTo(b) <= 0 ? a : b; }
    public static BigInteger max(BigInteger a, BigInteger b) { return a.compareTo(b) >= 0 ? a : b; }

    public static boolean within(BigInteger value, BigInteger lo, BigInteger hi) {
        return value.compareTo(lo) >= 0 && value.compareTo(hi) < 0;
    }

    public static BigInteger safediv(BigInteger a, BigInteger b) {
        if (b.signum() == 0) throw new ArithmeticException("safediv: division by zero");
        return a.divide(b);
    }

    public static BigInteger safemod(BigInteger a, BigInteger b) {
        if (b.signum() == 0) throw new ArithmeticException("safemod: division by zero");
        return a.remainder(b);
    }

    public static BigInteger clamp(BigInteger value, BigInteger lo, BigInteger hi) {
        if (value.compareTo(lo) < 0) return lo;
        if (value.compareTo(hi) > 0) return hi;
        return value;
    }

    public static BigInteger sign(BigInteger x) {
        return BigInteger.valueOf(x.signum());
    }

    public static BigInteger pow(BigInteger base, BigInteger exp) {
        if (exp.signum() < 0) throw new ArithmeticException("pow: negative exponent");
        BigInteger result = BigInteger.ONE;
        BigInteger b = base;
        BigInteger e = exp;
        while (e.signum() > 0) {
            if (e.testBit(0)) result = result.multiply(b);
            b = b.multiply(b);
            e = e.shiftRight(1);
        }
        return result;
    }

    public static BigInteger mulDiv(BigInteger a, BigInteger b, BigInteger c) {
        return a.multiply(b).divide(c);
    }

    public static BigInteger percentOf(BigInteger amount, BigInteger bps) {
        return amount.multiply(bps).divide(BigInteger.valueOf(10000));
    }

    public static BigInteger sqrt(BigInteger n) {
        if (n.signum() < 0) throw new ArithmeticException("sqrt: negative input");
        return n.sqrt();
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        return a.abs().gcd(b.abs());
    }

    public static BigInteger divmod(BigInteger a, BigInteger b) {
        return a.divide(b);
    }

    public static BigInteger log2(BigInteger n) {
        if (n.signum() <= 0) throw new ArithmeticException("log2: non-positive input");
        return BigInteger.valueOf(n.bitLength() - 1);
    }

    public static boolean bool(BigInteger x) {
        return x.signum() != 0;
    }

    // =======================================================================
    // ByteString ops — real
    // =======================================================================

    public static BigInteger len(ByteString bs) {
        return BigInteger.valueOf(bs.length());
    }

    public static ByteString cat(ByteString a, ByteString b) {
        byte[] ab = a.toByteArray();
        byte[] bb = b.toByteArray();
        byte[] out = new byte[ab.length + bb.length];
        System.arraycopy(ab, 0, out, 0, ab.length);
        System.arraycopy(bb, 0, out, ab.length, bb.length);
        return new ByteString(out);
    }

    public static ByteString substr(ByteString bs, BigInteger start, BigInteger length) {
        int s = start.intValueExact();
        int l = length.intValueExact();
        byte[] all = bs.toByteArray();
        return new ByteString(Arrays.copyOfRange(all, s, s + l));
    }

    public static ByteString left(ByteString bs, BigInteger length) {
        int l = length.intValueExact();
        return new ByteString(Arrays.copyOfRange(bs.toByteArray(), 0, l));
    }

    public static ByteString right(ByteString bs, BigInteger length) {
        int l = length.intValueExact();
        byte[] all = bs.toByteArray();
        return new ByteString(Arrays.copyOfRange(all, all.length - l, all.length));
    }

    /** Returns [left, right] split at byte index {@code index}. */
    public static ByteString[] split(ByteString bs, BigInteger index) {
        int i = index.intValueExact();
        byte[] all = bs.toByteArray();
        return new ByteString[] {
            new ByteString(Arrays.copyOfRange(all, 0, i)),
            new ByteString(Arrays.copyOfRange(all, i, all.length)),
        };
    }

    public static ByteString reverseBytes(ByteString bs) {
        byte[] all = bs.toByteArray();
        byte[] out = new byte[all.length];
        for (int i = 0; i < all.length; i++) out[i] = all[all.length - 1 - i];
        return new ByteString(out);
    }

    // =======================================================================
    // Script number encoding (num2bin / bin2num) — real
    // =======================================================================

    /** Bitcoin Script "number" encoding: little-endian sign-and-magnitude. */
    public static byte[] encodeScriptNumber(BigInteger n) {
        if (n.signum() == 0) return new byte[0];
        boolean negative = n.signum() < 0;
        BigInteger abs = n.abs();
        byte[] mag = abs.toByteArray();
        // Convert big-endian to little-endian and strip leading zero byte if any.
        int start = (mag[0] == 0) ? 1 : 0;
        int len = mag.length - start;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = mag[mag.length - 1 - i];
        }
        if ((out[out.length - 1] & 0x80) != 0) {
            byte[] extended = new byte[out.length + 1];
            System.arraycopy(out, 0, extended, 0, out.length);
            extended[out.length] = (byte) (negative ? 0x80 : 0x00);
            return extended;
        } else if (negative) {
            out[out.length - 1] |= (byte) 0x80;
        }
        return out;
    }

    public static BigInteger decodeScriptNumber(byte[] bytes) {
        if (bytes.length == 0) return BigInteger.ZERO;
        byte last = bytes[bytes.length - 1];
        boolean negative = (last & 0x80) != 0;
        // Build magnitude with the sign bit cleared.
        byte[] magLE = bytes.clone();
        if (negative) magLE[magLE.length - 1] = (byte) (last & 0x7f);
        // Little-endian → BigInteger.
        BigInteger result = BigInteger.ZERO;
        for (int i = magLE.length - 1; i >= 0; i--) {
            result = result.shiftLeft(8).or(BigInteger.valueOf(magLE[i] & 0xff));
        }
        return negative ? result.negate() : result;
    }

    public static ByteString num2bin(BigInteger value, BigInteger byteLen) {
        byte[] enc = encodeScriptNumber(value);
        int target = byteLen.intValueExact();
        if (enc.length > target) {
            throw new IllegalArgumentException("num2bin: value does not fit in " + target + " bytes");
        }
        byte[] out = new byte[target];
        // Pad with zeros; if sign bit needs to move to the MSB byte, relocate it.
        if (enc.length == 0) {
            return new ByteString(out);
        }
        boolean negative = (enc[enc.length - 1] & 0x80) != 0;
        if (negative) {
            // Clear the sign bit on the original last byte; move to padded MSB.
            for (int i = 0; i < enc.length; i++) out[i] = enc[i];
            out[enc.length - 1] = (byte) (out[enc.length - 1] & 0x7f);
            out[target - 1] = (byte) (out[target - 1] | 0x80);
        } else {
            System.arraycopy(enc, 0, out, 0, enc.length);
        }
        return new ByteString(out);
    }

    public static BigInteger bin2num(ByteString bs) {
        return decodeScriptNumber(bs.toByteArray());
    }

    public static ByteString int2str(BigInteger value, BigInteger byteLen) {
        return num2bin(value, byteLen);
    }

    // =======================================================================
    // EC (secp256k1) operations — real when BouncyCastle is on the classpath
    // =======================================================================

    public static final BigInteger EC_P =
        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    public static final BigInteger EC_N =
        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    /** Generator Gx. */
    private static final BigInteger GX =
        new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    /** Generator Gy. */
    private static final BigInteger GY =
        new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

    /** Point represented as (x, y) coordinates; null components mean the infinity point. */
    public static final class Point {
        public final BigInteger x;
        public final BigInteger y;
        public final boolean infinity;

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
            this.infinity = false;
        }

        private Point() {
            this.x = null;
            this.y = null;
            this.infinity = true;
        }

        public static final Point INFINITY = new Point();

        public byte[] toRaw64() {
            if (infinity) return new byte[64];
            byte[] out = new byte[64];
            byte[] xb = to32(x);
            byte[] yb = to32(y);
            System.arraycopy(xb, 0, out, 0, 32);
            System.arraycopy(yb, 0, out, 32, 32);
            return out;
        }

        public static Point fromRaw64(byte[] raw) {
            if (raw.length != 64) throw new IllegalArgumentException("expected 64 bytes");
            byte[] xb = Arrays.copyOfRange(raw, 0, 32);
            byte[] yb = Arrays.copyOfRange(raw, 32, 64);
            BigInteger x = new BigInteger(1, xb);
            BigInteger y = new BigInteger(1, yb);
            if (x.signum() == 0 && y.signum() == 0) return INFINITY;
            return new Point(x, y);
        }

        public ByteString toByteString() { return new ByteString(toRaw64()); }

        public String toHex() { return HEX.formatHex(toRaw64()); }

        @Override public boolean equals(Object o) {
            if (!(o instanceof Point p)) return false;
            if (this.infinity && p.infinity) return true;
            if (this.infinity != p.infinity) return false;
            return this.x.equals(p.x) && this.y.equals(p.y);
        }

        @Override public int hashCode() {
            return infinity ? 0 : x.hashCode() * 31 + y.hashCode();
        }

        @Override public String toString() { return infinity ? "Point(inf)" : "Point(" + x.toString(16) + ", " + y.toString(16) + ")"; }
    }

    private static byte[] to32(BigInteger v) {
        byte[] raw = v.toByteArray();
        if (raw.length == 32) return raw;
        if (raw.length == 33 && raw[0] == 0) return Arrays.copyOfRange(raw, 1, 33);
        if (raw.length > 32) throw new IllegalArgumentException("coord does not fit in 32 bytes");
        byte[] out = new byte[32];
        System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        return out;
    }

    public static final Point EC_G = new Point(GX, GY);

    /** Modular inverse mod EC_P. */
    private static BigInteger modInvP(BigInteger a) {
        return a.modInverse(EC_P);
    }

    private static BigInteger mod(BigInteger a, BigInteger m) {
        BigInteger r = a.mod(m);
        return r.signum() < 0 ? r.add(m) : r;
    }

    /** Add two secp256k1 points using affine formulas. */
    public static Point ecAdd(Point a, Point b) {
        if (a.infinity) return b;
        if (b.infinity) return a;
        if (a.x.equals(b.x)) {
            if (a.y.equals(b.y)) {
                // Doubling.
                BigInteger s = a.x.pow(2).multiply(BigInteger.valueOf(3))
                    .multiply(modInvP(a.y.multiply(BigInteger.valueOf(2))));
                s = mod(s, EC_P);
                BigInteger xr = mod(s.pow(2).subtract(a.x.multiply(BigInteger.valueOf(2))), EC_P);
                BigInteger yr = mod(s.multiply(a.x.subtract(xr)).subtract(a.y), EC_P);
                return new Point(xr, yr);
            }
            return Point.INFINITY;
        }
        BigInteger s = mod(b.y.subtract(a.y).multiply(modInvP(b.x.subtract(a.x))), EC_P);
        BigInteger xr = mod(s.pow(2).subtract(a.x).subtract(b.x), EC_P);
        BigInteger yr = mod(s.multiply(a.x.subtract(xr)).subtract(a.y), EC_P);
        return new Point(xr, yr);
    }

    /** Scalar multiplication via double-and-add. */
    public static Point ecMul(Point p, BigInteger k) {
        BigInteger scalar = mod(k, EC_N);
        Point result = Point.INFINITY;
        Point addend = p;
        while (scalar.signum() > 0) {
            if (scalar.testBit(0)) result = ecAdd(result, addend);
            addend = ecAdd(addend, addend);
            scalar = scalar.shiftRight(1);
        }
        return result;
    }

    public static Point ecMulGen(BigInteger k) {
        return ecMul(EC_G, k);
    }

    public static Point ecNegate(Point p) {
        if (p.infinity) return p;
        return new Point(p.x, EC_P.subtract(p.y));
    }

    public static boolean ecOnCurve(Point p) {
        if (p.infinity) return true;
        BigInteger lhs = mod(p.y.pow(2), EC_P);
        BigInteger rhs = mod(p.x.pow(3).add(BigInteger.valueOf(7)), EC_P);
        return lhs.equals(rhs);
    }

    public static BigInteger ecModReduce(BigInteger value, BigInteger modulus) {
        return mod(value, modulus);
    }

    public static ByteString ecEncodeCompressed(Point p) {
        byte[] out = new byte[33];
        out[0] = (byte) (p.y.testBit(0) ? 0x03 : 0x02);
        System.arraycopy(to32(p.x), 0, out, 1, 32);
        return new ByteString(out);
    }

    public static Point ecMakePoint(BigInteger x, BigInteger y) {
        return new Point(x, y);
    }

    public static BigInteger ecPointX(Point p) { return p.x; }
    public static BigInteger ecPointY(Point p) { return p.y; }

    // =======================================================================
    // Field arithmetic — stubbed
    // =======================================================================
    //
    // BabyBear, KoalaBear, BN254, Poseidon2 are used exclusively inside
    // proof-system verification circuits. Porting those to Java for the
    // simulator is tractable but outside the M11 scope (M11 explicitly
    // says "can stub if full impl is intractable in scope; document").
    // Contracts that exercise proof-system primitives should test via
    // the compiler+VM path instead of the simulator.

    private static final BigInteger BB_P = BigInteger.valueOf(2013265921L);
    private static final BigInteger KB_P = BigInteger.valueOf(2130706433L);

    public static BigInteger bbFieldAdd(BigInteger a, BigInteger b) { return mod(a.add(b), BB_P); }
    public static BigInteger bbFieldSub(BigInteger a, BigInteger b) { return mod(a.subtract(b), BB_P); }
    public static BigInteger bbFieldMul(BigInteger a, BigInteger b) { return mod(a.multiply(b), BB_P); }
    public static BigInteger bbFieldInv(BigInteger a) { return a.modInverse(BB_P); }

    public static BigInteger kbFieldAdd(BigInteger a, BigInteger b) { return mod(a.add(b), KB_P); }
    public static BigInteger kbFieldSub(BigInteger a, BigInteger b) { return mod(a.subtract(b), KB_P); }
    public static BigInteger kbFieldMul(BigInteger a, BigInteger b) { return mod(a.multiply(b), KB_P); }
    public static BigInteger kbFieldInv(BigInteger a) { return a.modInverse(KB_P); }

    // Poseidon2 / BN254 — not implemented in the Java simulator. Full
    // ports are out of scope; proof-system circuits are not exercisable
    // off-chain at byte-level fidelity. Calls now fail loudly instead of
    // silently returning zero.
    public static BigInteger poseidon2Hash(BigInteger... inputs) {
        throw new UnsupportedOperationException(
            "MockCrypto.poseidon2Hash is not implemented in the Java simulator — "
            + "test proof-system contracts via the compiler+VM path (Go is authoritative for BN254/Poseidon2).");
    }

    public static BigInteger bn254FieldAdd(BigInteger a, BigInteger b) {
        throw new UnsupportedOperationException(
            "MockCrypto.bn254FieldAdd is not implemented in the Java simulator — "
            + "test proof-system contracts via the compiler+VM path (Go is authoritative for BN254/Poseidon2).");
    }
    public static BigInteger bn254FieldMul(BigInteger a, BigInteger b) {
        throw new UnsupportedOperationException(
            "MockCrypto.bn254FieldMul is not implemented in the Java simulator — "
            + "test proof-system contracts via the compiler+VM path (Go is authoritative for BN254/Poseidon2).");
    }

    // =======================================================================
    // Merkle proof verification — real (SHA-256 based)
    // =======================================================================

    public static ByteString merkleRootSha256(ByteString leaf, ByteString proof, BigInteger index, BigInteger depth) {
        return merkleRootImpl(leaf, proof, index, depth.intValueExact(), false);
    }

    public static ByteString merkleRootHash256(ByteString leaf, ByteString proof, BigInteger index, BigInteger depth) {
        return merkleRootImpl(leaf, proof, index, depth.intValueExact(), true);
    }

    private static ByteString merkleRootImpl(ByteString leaf, ByteString proof, BigInteger index, int depth, boolean doubleSha) {
        byte[] current = leaf.toByteArray();
        byte[] proofBytes = proof.toByteArray();
        for (int i = 0; i < depth; i++) {
            byte[] sibling = Arrays.copyOfRange(proofBytes, i * 32, (i + 1) * 32);
            boolean right = index.testBit(i);
            byte[] combined = new byte[64];
            if (right) {
                System.arraycopy(sibling, 0, combined, 0, 32);
                System.arraycopy(current, 0, combined, 32, 32);
            } else {
                System.arraycopy(current, 0, combined, 0, 32);
                System.arraycopy(sibling, 0, combined, 32, 32);
            }
            current = doubleSha ? hash256(combined) : sha256(combined);
        }
        return new ByteString(current);
    }

    // =======================================================================
    // SHA-256 compression primitives — real (FIPS 180-4 §6.2.2)
    // =======================================================================

    private static final int[] SHA256_K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    /** SHA-256 IV (FIPS 180-4 §5.3.3). */
    public static final byte[] SHA256_IV = sha256IvBytes();

    private static byte[] sha256IvBytes() {
        int[] iv = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        };
        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) packBE32(out, i * 4, iv[i]);
        return out;
    }

    private static int rotr32(int x, int n) {
        return (x >>> n) | (x << (32 - n));
    }

    private static int unpackBE32(byte[] b, int off) {
        return ((b[off] & 0xff) << 24)
             | ((b[off + 1] & 0xff) << 16)
             | ((b[off + 2] & 0xff) << 8)
             | (b[off + 3] & 0xff);
    }

    private static void packBE32(byte[] b, int off, int v) {
        b[off]     = (byte) (v >>> 24);
        b[off + 1] = (byte) (v >>> 16);
        b[off + 2] = (byte) (v >>> 8);
        b[off + 3] = (byte) v;
    }

    /**
     * SHA-256 single-block compression (FIPS 180-4 §6.2.2). Mirrors
     * {@code sha256_compress} in {@code packages/runar-py/runar/builtins.py}
     * and the on-chain Script codegen in
     * {@code compilers/java/src/main/java/runar/compiler/codegen/Sha256.java}.
     *
     * @param state 32-byte intermediate hash state (8 big-endian uint32s).
     *              Use {@link #SHA256_IV} for the first block.
     * @param block 64-byte message block (512 bits).
     * @return updated 32-byte state.
     */
    public static ByteString sha256Compress(ByteString state, ByteString block) {
        byte[] s = state.toByteArray();
        byte[] m = block.toByteArray();
        if (s.length != 32) throw new IllegalArgumentException("sha256Compress: state must be 32 bytes, got " + s.length);
        if (m.length != 64) throw new IllegalArgumentException("sha256Compress: block must be 64 bytes, got " + m.length);

        int[] H = new int[8];
        for (int i = 0; i < 8; i++) H[i] = unpackBE32(s, i * 4);

        int[] W = new int[64];
        for (int i = 0; i < 16; i++) W[i] = unpackBE32(m, i * 4);
        for (int t = 16; t < 64; t++) {
            int s0 = rotr32(W[t - 15], 7) ^ rotr32(W[t - 15], 18) ^ (W[t - 15] >>> 3);
            int s1 = rotr32(W[t - 2], 17) ^ rotr32(W[t - 2], 19) ^ (W[t - 2] >>> 10);
            W[t] = W[t - 16] + s0 + W[t - 7] + s1;
        }

        int a = H[0], b = H[1], c = H[2], d = H[3];
        int e = H[4], f = H[5], g = H[6], h = H[7];

        for (int t = 0; t < 64; t++) {
            int S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            int ch = (e & f) ^ (~e & g);
            int t1 = h + S1 + ch + SHA256_K[t] + W[t];
            int S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            int maj = (a & b) ^ (a & c) ^ (b & c);
            int t2 = S0 + maj;
            h = g; g = f; f = e;
            e = d + t1;
            d = c; c = b; b = a;
            a = t1 + t2;
        }

        byte[] out = new byte[32];
        packBE32(out, 0, H[0] + a);
        packBE32(out, 4, H[1] + b);
        packBE32(out, 8, H[2] + c);
        packBE32(out, 12, H[3] + d);
        packBE32(out, 16, H[4] + e);
        packBE32(out, 20, H[5] + f);
        packBE32(out, 24, H[6] + g);
        packBE32(out, 28, H[7] + h);
        return new ByteString(out);
    }

    /**
     * SHA-256 finalization with FIPS 180-4 padding. Appends the 0x80
     * marker, zero-pads, and writes the 8-byte big-endian total bit
     * length, then runs the final 1 or 2 compression rounds.
     *
     * @param state       intermediate state (use {@link #SHA256_IV} for
     *                    a single-block message).
     * @param remaining   trailing message bytes not yet compressed (0..119).
     * @param msgBitLen   total message length in bits across all blocks.
     */
    public static ByteString sha256Finalize(ByteString state, ByteString remaining, BigInteger msgBitLen) {
        byte[] rem = remaining.toByteArray();
        if (rem.length > 119) {
            throw new IllegalArgumentException("sha256Finalize: remaining must be 0..119 bytes, got " + rem.length);
        }
        long bitLen = msgBitLen.longValueExact();

        // remaining || 0x80 || zero-pad || bitLen(8 bytes BE)
        int padded1Len = rem.length + 1;
        boolean twoBlocks = padded1Len + 8 > 64;
        int totalLen = twoBlocks ? 128 : 64;
        byte[] padded = new byte[totalLen];
        System.arraycopy(rem, 0, padded, 0, rem.length);
        padded[rem.length] = (byte) 0x80;
        // bit length at last 8 bytes (big-endian).
        for (int i = 0; i < 8; i++) {
            padded[totalLen - 1 - i] = (byte) (bitLen >>> (8 * i));
        }

        ByteString s = state;
        if (twoBlocks) {
            s = sha256Compress(s, new ByteString(Arrays.copyOfRange(padded, 0, 64)));
            return sha256Compress(s, new ByteString(Arrays.copyOfRange(padded, 64, 128)));
        }
        return sha256Compress(s, new ByteString(padded));
    }

    // =======================================================================
    // Hex utilities
    // =======================================================================

    public static String toHex(byte[] bytes) { return HEX.formatHex(bytes); }
    public static byte[] fromHex(String hex) { return HEX.parseHex(hex); }
}
