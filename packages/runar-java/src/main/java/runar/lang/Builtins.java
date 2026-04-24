package runar.lang;

import java.math.BigInteger;

import runar.lang.runtime.MockCrypto;
import runar.lang.runtime.Preimage;
import runar.lang.runtime.SimulatorContext;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

/**
 * Rúnar built-in functions, as static methods for import-static use
 * inside contract source files.
 *
 * <p>The compiler treats every method here as an AST-level intrinsic:
 * the call never runs on-chain (the Bitcoin Script VM executes the
 * compiled opcode form). For off-chain unit testing we provide a
 * simulator (see {@code runar.lang.runtime}) that flips a thread-local
 * flag; inside the simulator these methods delegate to real
 * implementations in {@link MockCrypto}. Outside the simulator they
 * throw {@link UnsupportedOperationException} — calling a builtin from
 * plain Java is a programming error.
 */
public final class Builtins {

    private Builtins() {}

    private static UnsupportedOperationException notInSimulator(String name) {
        return new UnsupportedOperationException(
            name + " is a compile-time intrinsic; enter the off-chain simulator "
            + "(runar.lang.runtime.ContractSimulator) to invoke it from Java"
        );
    }

    // ===================================================================
    // Assertions — work at runtime regardless of simulator mode.
    // ===================================================================

    public static void assertThat(boolean condition) {
        if (!condition) throw new AssertionError("Rúnar contract assertion failed");
    }

    // ===================================================================
    // Hashing
    // ===================================================================

    public static Addr hash160(PubKey pubKey) {
        if (!SimulatorContext.isActive()) throw notInSimulator("hash160");
        return MockCrypto.hash160(pubKey);
    }

    public static Addr hash160(ByteString data) {
        if (!SimulatorContext.isActive()) throw notInSimulator("hash160");
        return MockCrypto.hash160(data);
    }

    public static ByteString sha256(ByteString data) {
        if (!SimulatorContext.isActive()) throw notInSimulator("sha256");
        return MockCrypto.sha256(data);
    }

    public static ByteString ripemd160(ByteString data) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ripemd160");
        return MockCrypto.ripemd160(data);
    }

    public static ByteString hash256(ByteString data) {
        if (!SimulatorContext.isActive()) throw notInSimulator("hash256");
        return MockCrypto.hash256(data);
    }

    public static ByteString sha256Compress(ByteString state, ByteString block) {
        if (!SimulatorContext.isActive()) throw notInSimulator("sha256Compress");
        return MockCrypto.sha256Compress(state, block);
    }

    public static ByteString sha256Finalize(ByteString state, ByteString remaining, BigInteger msgBitLen) {
        if (!SimulatorContext.isActive()) throw notInSimulator("sha256Finalize");
        return MockCrypto.sha256Finalize(state, remaining, msgBitLen);
    }

    // ===================================================================
    // Signature verification
    // ===================================================================

    public static boolean checkSig(Sig sig, PubKey pubKey) {
        if (!SimulatorContext.isActive()) throw notInSimulator("checkSig");
        return MockCrypto.checkSig(sig, pubKey);
    }

    public static boolean checkMultiSig(Sig[] sigs, PubKey[] pubKeys) {
        if (!SimulatorContext.isActive()) throw notInSimulator("checkMultiSig");
        return MockCrypto.checkMultiSig(sigs, pubKeys);
    }

    public static boolean verifyRabinSig(ByteString msg, BigInteger sig, ByteString padding, BigInteger pubKey) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifyRabinSig");
        return MockCrypto.verifyRabinSig(msg, sig, padding, pubKey);
    }

    public static boolean verifyWOTS(ByteString msg, ByteString sig, ByteString pubKey) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifyWOTS");
        return MockCrypto.verifyWOTS(msg, sig, pubKey);
    }

    public static boolean verifySLHDSA_SHA2_128s(ByteString msg, ByteString sig, ByteString pk) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifySLHDSA_SHA2_128s");
        return MockCrypto.verifySLHDSA_SHA2_128s(msg, sig, pk);
    }
    public static boolean verifySLHDSA_SHA2_128f(ByteString msg, ByteString sig, ByteString pk) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifySLHDSA_SHA2_128f");
        return MockCrypto.verifySLHDSA_SHA2_128f(msg, sig, pk);
    }
    public static boolean verifySLHDSA_SHA2_192s(ByteString msg, ByteString sig, ByteString pk) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifySLHDSA_SHA2_192s");
        return MockCrypto.verifySLHDSA_SHA2_192s(msg, sig, pk);
    }
    public static boolean verifySLHDSA_SHA2_192f(ByteString msg, ByteString sig, ByteString pk) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifySLHDSA_SHA2_192f");
        return MockCrypto.verifySLHDSA_SHA2_192f(msg, sig, pk);
    }
    public static boolean verifySLHDSA_SHA2_256s(ByteString msg, ByteString sig, ByteString pk) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifySLHDSA_SHA2_256s");
        return MockCrypto.verifySLHDSA_SHA2_256s(msg, sig, pk);
    }
    public static boolean verifySLHDSA_SHA2_256f(ByteString msg, ByteString sig, ByteString pk) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifySLHDSA_SHA2_256f");
        return MockCrypto.verifySLHDSA_SHA2_256f(msg, sig, pk);
    }

    // ===================================================================
    // Math (BigInteger)
    // ===================================================================

    public static BigInteger abs(BigInteger x) {
        if (!SimulatorContext.isActive()) throw notInSimulator("abs");
        return MockCrypto.abs(x);
    }
    public static BigInteger min(BigInteger a, BigInteger b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("min");
        return MockCrypto.min(a, b);
    }
    public static BigInteger max(BigInteger a, BigInteger b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("max");
        return MockCrypto.max(a, b);
    }
    public static boolean within(BigInteger v, BigInteger lo, BigInteger hi) {
        if (!SimulatorContext.isActive()) throw notInSimulator("within");
        return MockCrypto.within(v, lo, hi);
    }
    public static BigInteger safediv(BigInteger a, BigInteger b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("safediv");
        return MockCrypto.safediv(a, b);
    }
    public static BigInteger safemod(BigInteger a, BigInteger b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("safemod");
        return MockCrypto.safemod(a, b);
    }
    public static BigInteger clamp(BigInteger v, BigInteger lo, BigInteger hi) {
        if (!SimulatorContext.isActive()) throw notInSimulator("clamp");
        return MockCrypto.clamp(v, lo, hi);
    }
    public static BigInteger sign(BigInteger x) {
        if (!SimulatorContext.isActive()) throw notInSimulator("sign");
        return MockCrypto.sign(x);
    }
    public static BigInteger pow(BigInteger b, BigInteger e) {
        if (!SimulatorContext.isActive()) throw notInSimulator("pow");
        return MockCrypto.pow(b, e);
    }
    public static BigInteger mulDiv(BigInteger a, BigInteger b, BigInteger c) {
        if (!SimulatorContext.isActive()) throw notInSimulator("mulDiv");
        return MockCrypto.mulDiv(a, b, c);
    }
    public static BigInteger percentOf(BigInteger a, BigInteger bps) {
        if (!SimulatorContext.isActive()) throw notInSimulator("percentOf");
        return MockCrypto.percentOf(a, bps);
    }
    public static BigInteger sqrt(BigInteger n) {
        if (!SimulatorContext.isActive()) throw notInSimulator("sqrt");
        return MockCrypto.sqrt(n);
    }
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("gcd");
        return MockCrypto.gcd(a, b);
    }
    public static BigInteger log2(BigInteger n) {
        if (!SimulatorContext.isActive()) throw notInSimulator("log2");
        return MockCrypto.log2(n);
    }
    public static boolean bool(BigInteger v) {
        if (!SimulatorContext.isActive()) throw notInSimulator("bool");
        return MockCrypto.bool(v);
    }

    // ===================================================================
    // ByteString ops
    // ===================================================================

    public static BigInteger len(ByteString bs) {
        if (!SimulatorContext.isActive()) throw notInSimulator("len");
        return MockCrypto.len(bs);
    }
    public static ByteString cat(ByteString a, ByteString b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("cat");
        return MockCrypto.cat(a, b);
    }
    public static ByteString substr(ByteString bs, BigInteger start, BigInteger len) {
        if (!SimulatorContext.isActive()) throw notInSimulator("substr");
        return MockCrypto.substr(bs, start, len);
    }
    public static ByteString left(ByteString bs, BigInteger len) {
        if (!SimulatorContext.isActive()) throw notInSimulator("left");
        return MockCrypto.left(bs, len);
    }
    public static ByteString right(ByteString bs, BigInteger len) {
        if (!SimulatorContext.isActive()) throw notInSimulator("right");
        return MockCrypto.right(bs, len);
    }
    public static ByteString[] split(ByteString bs, BigInteger idx) {
        if (!SimulatorContext.isActive()) throw notInSimulator("split");
        return MockCrypto.split(bs, idx);
    }
    public static ByteString reverseBytes(ByteString bs) {
        if (!SimulatorContext.isActive()) throw notInSimulator("reverseBytes");
        return MockCrypto.reverseBytes(bs);
    }
    public static ByteString num2bin(BigInteger v, BigInteger len) {
        if (!SimulatorContext.isActive()) throw notInSimulator("num2bin");
        return MockCrypto.num2bin(v, len);
    }
    public static BigInteger bin2num(ByteString bs) {
        if (!SimulatorContext.isActive()) throw notInSimulator("bin2num");
        return MockCrypto.bin2num(bs);
    }
    public static ByteString int2str(BigInteger v, BigInteger len) {
        if (!SimulatorContext.isActive()) throw notInSimulator("int2str");
        return MockCrypto.int2str(v, len);
    }

    // ===================================================================
    // EC operations
    // ===================================================================

    public static MockCrypto.Point ecAdd(MockCrypto.Point a, MockCrypto.Point b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecAdd");
        return MockCrypto.ecAdd(a, b);
    }
    public static MockCrypto.Point ecMul(MockCrypto.Point p, BigInteger k) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecMul");
        return MockCrypto.ecMul(p, k);
    }
    public static MockCrypto.Point ecMulGen(BigInteger k) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecMulGen");
        return MockCrypto.ecMulGen(k);
    }
    public static MockCrypto.Point ecNegate(MockCrypto.Point p) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecNegate");
        return MockCrypto.ecNegate(p);
    }
    public static boolean ecOnCurve(MockCrypto.Point p) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecOnCurve");
        return MockCrypto.ecOnCurve(p);
    }
    public static BigInteger ecModReduce(BigInteger v, BigInteger m) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecModReduce");
        return MockCrypto.ecModReduce(v, m);
    }
    public static ByteString ecEncodeCompressed(MockCrypto.Point p) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecEncodeCompressed");
        return MockCrypto.ecEncodeCompressed(p);
    }
    public static MockCrypto.Point ecMakePoint(BigInteger x, BigInteger y) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecMakePoint");
        return MockCrypto.ecMakePoint(x, y);
    }
    public static BigInteger ecPointX(MockCrypto.Point p) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecPointX");
        return MockCrypto.ecPointX(p);
    }
    public static BigInteger ecPointY(MockCrypto.Point p) {
        if (!SimulatorContext.isActive()) throw notInSimulator("ecPointY");
        return MockCrypto.ecPointY(p);
    }

    // ===================================================================
    // Preimage
    // ===================================================================

    public static boolean checkPreimage(Preimage preimage) {
        if (!SimulatorContext.isActive()) throw notInSimulator("checkPreimage");
        return Preimage.checkPreimage(preimage);
    }
}
