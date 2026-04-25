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
 * Post-quantum verifications (WOTS, SLH-DSA variants), SHA-256 partial
 * compression (sha256Compress / sha256Finalize), and BN254 / Poseidon2
 * primitives are not implemented in the simulator; calling them throws
 * {@link UnsupportedOperationException}. Contracts that exercise those
 * primitives should be unit-tested via the compiler+VM path rather than
 * the simulator.
 *
 * <p>BabyBear and KoalaBear field arithmetic remain real (small primes,
 * trivial BigInteger ports).
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

    public static boolean verifyWOTS(ByteString msg, ByteString sig, ByteString pubKey) {
        throw new UnsupportedOperationException(
            "MockCrypto.verifyWOTS is not implemented in the Java simulator — "
            + "test post-quantum contracts via the compiler+VM path instead.");
    }

    public static boolean verifySLHDSA_SHA2_128s(ByteString msg, ByteString sig, ByteString pubKey) {
        throw new UnsupportedOperationException(
            "MockCrypto.verifySLHDSA_SHA2_128s is not implemented in the Java simulator — "
            + "test post-quantum contracts via the compiler+VM path instead.");
    }
    public static boolean verifySLHDSA_SHA2_128f(ByteString msg, ByteString sig, ByteString pubKey) {
        throw new UnsupportedOperationException(
            "MockCrypto.verifySLHDSA_SHA2_128f is not implemented in the Java simulator — "
            + "test post-quantum contracts via the compiler+VM path instead.");
    }
    public static boolean verifySLHDSA_SHA2_192s(ByteString msg, ByteString sig, ByteString pubKey) {
        throw new UnsupportedOperationException(
            "MockCrypto.verifySLHDSA_SHA2_192s is not implemented in the Java simulator — "
            + "test post-quantum contracts via the compiler+VM path instead.");
    }
    public static boolean verifySLHDSA_SHA2_192f(ByteString msg, ByteString sig, ByteString pubKey) {
        throw new UnsupportedOperationException(
            "MockCrypto.verifySLHDSA_SHA2_192f is not implemented in the Java simulator — "
            + "test post-quantum contracts via the compiler+VM path instead.");
    }
    public static boolean verifySLHDSA_SHA2_256s(ByteString msg, ByteString sig, ByteString pubKey) {
        throw new UnsupportedOperationException(
            "MockCrypto.verifySLHDSA_SHA2_256s is not implemented in the Java simulator — "
            + "test post-quantum contracts via the compiler+VM path instead.");
    }
    public static boolean verifySLHDSA_SHA2_256f(ByteString msg, ByteString sig, ByteString pubKey) {
        throw new UnsupportedOperationException(
            "MockCrypto.verifySLHDSA_SHA2_256f is not implemented in the Java simulator — "
            + "test post-quantum contracts via the compiler+VM path instead.");
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
    // SHA-256 compression primitives — not implemented
    // =======================================================================
    //
    // sha256Compress / sha256Finalize expose the compression function
    // directly to contracts that build partial SHA-256 inductively (Rabin,
    // WOTS). The simulator can't exercise them meaningfully without a
    // real SHA-256 compression-function implementation; calls now fail
    // loudly instead of silently returning the input state unchanged
    // (which used to hide bugs in inductive-hash contracts).
    public static ByteString sha256Compress(ByteString state, ByteString block) {
        throw new UnsupportedOperationException(
            "MockCrypto.sha256Compress is not implemented in the Java simulator — "
            + "test SHA-256-inductive contracts (Rabin, WOTS) via the compiler+VM path.");
    }

    public static ByteString sha256Finalize(ByteString state, ByteString remaining, BigInteger msgBitLen) {
        throw new UnsupportedOperationException(
            "MockCrypto.sha256Finalize is not implemented in the Java simulator — "
            + "test SHA-256-inductive contracts (Rabin, WOTS) via the compiler+VM path.");
    }

    // =======================================================================
    // Hex utilities
    // =======================================================================

    public static String toHex(byte[] bytes) { return HEX.formatHex(bytes); }
    public static byte[] fromHex(String hex) { return HEX.parseHex(hex); }
}
