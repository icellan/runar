package runar.lang;

import java.math.BigInteger;

import runar.lang.runtime.MockCrypto;
import runar.lang.runtime.Preimage;
import runar.lang.runtime.SimulatorContext;
import runar.lang.types.Addr;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.RabinPubKey;
import runar.lang.types.RabinSig;
import runar.lang.types.Sig;
import runar.lang.types.SigHashPreimage;

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

    public static boolean verifyECDSA_P256(ByteString msg, ByteString sig, ByteString pk) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifyECDSA_P256");
        return MockCrypto.verifyECDSA_P256(msg, sig, pk);
    }
    public static boolean verifyECDSA_P384(ByteString msg, ByteString sig, ByteString pk) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifyECDSA_P384");
        return MockCrypto.verifyECDSA_P384(msg, sig, pk);
    }

    public static ByteString blake3Hash(ByteString data) {
        if (!SimulatorContext.isActive()) throw notInSimulator("blake3Hash");
        return MockCrypto.blake3Hash(data);
    }
    public static ByteString blake3Compress(ByteString state, ByteString block) {
        if (!SimulatorContext.isActive()) throw notInSimulator("blake3Compress");
        return MockCrypto.blake3Compress(state, block);
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
    /**
     * Convenience overload accepting two {@link MockCrypto.Point}s — the
     * Rúnar {@code Point} primitive is structurally a 64-byte ByteString
     * (x[32] || y[32]); canonical TS sources pass Points directly to
     * {@code cat}, and the off-chain simulator coerces each Point to its
     * raw 64-byte form so the IR produced by every frontend matches.
     */
    public static ByteString cat(MockCrypto.Point a, MockCrypto.Point b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("cat");
        return MockCrypto.cat(a.toByteString(), b.toByteString());
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
    /**
     * Convenience overload accepting {@link Bigint} for both arguments.
     * Mirrors the BigInteger form so Rúnar Java sources can pass the
     * wrapper type directly without unwrapping via {@code .value()}.
     */
    public static ByteString num2bin(Bigint v, Bigint len) {
        if (!SimulatorContext.isActive()) throw notInSimulator("num2bin");
        return MockCrypto.num2bin(v.value(), len.value());
    }
    /**
     * Mixed-arity convenience overload — receiver as {@link Bigint},
     * length as {@link BigInteger}. Useful when the length is a literal
     * {@code BigInteger.valueOf(8)} but the value is a contract field.
     */
    public static ByteString num2bin(Bigint v, BigInteger len) {
        if (!SimulatorContext.isActive()) throw notInSimulator("num2bin");
        return MockCrypto.num2bin(v.value(), len);
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
    // NIST P-256 (secp256r1) EC operations — compile-time intrinsics.
    // ===================================================================
    //
    // The Rúnar Java compiler emits real Bitcoin Script for these
    // primitives via the P256P384 codegen module. Off-chain we do not yet
    // ship a P-256 mock implementation, so calling these methods from
    // Java throws {@code notInSimulator}. Surface-level instantiation
    // tests (which never invoke the methods) work fine; richer simulator
    // support is tracked in M19.

    public static runar.lang.types.P256Point p256Add(runar.lang.types.P256Point a, runar.lang.types.P256Point b) {
        throw notInSimulator("p256Add");
    }
    public static runar.lang.types.P256Point p256Mul(runar.lang.types.P256Point p, BigInteger k) {
        throw notInSimulator("p256Mul");
    }
    public static runar.lang.types.P256Point p256MulGen(BigInteger k) {
        throw notInSimulator("p256MulGen");
    }
    public static runar.lang.types.P256Point p256Negate(runar.lang.types.P256Point p) {
        throw notInSimulator("p256Negate");
    }
    public static boolean p256OnCurve(runar.lang.types.P256Point p) {
        throw notInSimulator("p256OnCurve");
    }
    public static ByteString p256EncodeCompressed(runar.lang.types.P256Point p) {
        throw notInSimulator("p256EncodeCompressed");
    }

    // ===================================================================
    // NIST P-384 (secp384r1) EC operations — compile-time intrinsics.
    // ===================================================================

    public static runar.lang.types.P384Point p384Add(runar.lang.types.P384Point a, runar.lang.types.P384Point b) {
        throw notInSimulator("p384Add");
    }
    public static runar.lang.types.P384Point p384Mul(runar.lang.types.P384Point p, BigInteger k) {
        throw notInSimulator("p384Mul");
    }
    public static runar.lang.types.P384Point p384MulGen(BigInteger k) {
        throw notInSimulator("p384MulGen");
    }
    public static runar.lang.types.P384Point p384Negate(runar.lang.types.P384Point p) {
        throw notInSimulator("p384Negate");
    }
    public static boolean p384OnCurve(runar.lang.types.P384Point p) {
        throw notInSimulator("p384OnCurve");
    }
    public static ByteString p384EncodeCompressed(runar.lang.types.P384Point p) {
        throw notInSimulator("p384EncodeCompressed");
    }

    // ===================================================================
    // Preimage (structured)
    // ===================================================================

    public static boolean checkPreimage(Preimage preimage) {
        if (!SimulatorContext.isActive()) throw notInSimulator("checkPreimage");
        return Preimage.checkPreimage(preimage);
    }

    /**
     * {@code SigHashPreimage}-typed overload. The Rúnar compiler treats
     * {@link Preimage} and {@link SigHashPreimage} as two surfaces of
     * the same thing: the structured Java {@code Preimage} builder used
     * by tests, and the opaque-bytes {@code SigHashPreimage} that
     * contract source declares. This overload lets contracts written
     * against {@link SigHashPreimage} compile under the simulator.
     */
    public static boolean checkPreimage(SigHashPreimage preimage) {
        if (!SimulatorContext.isActive()) throw notInSimulator("checkPreimage");
        return true;
    }

    // ===================================================================
    // Preimage field extractors — mirror the OP_PUSH_TX opcode family.
    // The Rúnar compiler lowers these to the corresponding byte-window
    // opcodes; under the simulator they delegate to the structured
    // {@link Preimage} accessors and return sensible defaults when the
    // test has not explicitly built a preimage.
    // ===================================================================

    // SigHashPreimage overloads resolve through the simulator's active
    // Preimage when one is set; otherwise they return the Preimage
    // defaults (version = 1, locktime = 0, etc.).
    private static Preimage resolvePreimage(SigHashPreimage unused) {
        return SimulatorContext.currentPreimage();
    }

    public static BigInteger extractVersion(SigHashPreimage p) { return Preimage.extractVersion(resolvePreimage(p)); }
    public static BigInteger extractVersion(Preimage p) { return Preimage.extractVersion(p); }

    public static ByteString extractHashPrevouts(SigHashPreimage p) { return Preimage.extractHashPrevouts(resolvePreimage(p)); }
    public static ByteString extractHashPrevouts(Preimage p) { return Preimage.extractHashPrevouts(p); }

    public static ByteString extractOutpoint(SigHashPreimage p) { return Preimage.extractOutpoint(resolvePreimage(p)); }
    public static ByteString extractOutpoint(Preimage p) { return Preimage.extractOutpoint(p); }

    public static BigInteger extractLocktime(SigHashPreimage p) { return Preimage.extractLocktime(resolvePreimage(p)); }
    public static BigInteger extractLocktime(Preimage p) { return Preimage.extractLocktime(p); }

    public static ByteString extractOutputHash(SigHashPreimage p) {
        // Mirror packages/runar-lang/src/runtime/preimage.ts: when the
        // caller passes a SigHashPreimage whose first 32 bytes hold a
        // synthetic outputs-hash (the standard test pattern — set the
        // preimage to {@code hash256(expectedOutputs)}), echo those
        // bytes directly so the contract assertion
        // {@code hash256(outputs) === extractOutputHash(preimage)}
        // round-trips under stateless calls. For stateful contracts the
        // simulator threads a real {@link Preimage} via
        // {@link SimulatorContext} — fall back to that when the
        // SigHashPreimage parameter is empty.
        if (p != null && p.length() >= 32) {
            byte[] raw = p.toByteArray();
            return new ByteString(java.util.Arrays.copyOfRange(raw, 0, 32));
        }
        return Preimage.extractOutputHash(resolvePreimage(p));
    }
    public static ByteString extractOutputHash(Preimage p) { return Preimage.extractOutputHash(p); }

    public static BigInteger extractAmount(SigHashPreimage p) { return Preimage.extractAmount(resolvePreimage(p)); }
    public static BigInteger extractAmount(Preimage p) { return Preimage.extractAmount(p); }

    public static BigInteger extractSigHashType(SigHashPreimage p) { return Preimage.extractSigHashType(resolvePreimage(p)); }
    public static BigInteger extractSigHashType(Preimage p) { return Preimage.extractSigHashType(p); }

    // ===================================================================
    // Rabin-typed overloads. Rabin signatures / pub keys are plain big
    // integers on-chain; the wrapper types carry semantic intent.
    // ===================================================================

    public static boolean verifyRabinSig(ByteString msg, RabinSig sig, ByteString padding, RabinPubKey pubKey) {
        if (!SimulatorContext.isActive()) throw notInSimulator("verifyRabinSig");
        return MockCrypto.verifyRabinSig(msg, sig.value(), padding, pubKey.value());
    }

    // ===================================================================
    // Baby Bear prime field arithmetic (Bigint-typed shims).
    //
    // The Rúnar Java compiler recognises these names as Go-only crypto
    // builtins and emits no Stack-IR for them yet — but Rúnar contracts
    // written in Java still need to call them through the canonical
    // {@code Bigint}-typed surface so the source parses, validates, and
    // typechecks cleanly. Each shim delegates to {@link MockCrypto} for
    // off-chain simulation.
    // ===================================================================

    public static Bigint bbFieldAdd(Bigint a, Bigint b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("bbFieldAdd");
        return new Bigint(MockCrypto.bbFieldAdd(a.value(), b.value()));
    }
    public static Bigint bbFieldSub(Bigint a, Bigint b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("bbFieldSub");
        return new Bigint(MockCrypto.bbFieldSub(a.value(), b.value()));
    }
    public static Bigint bbFieldMul(Bigint a, Bigint b) {
        if (!SimulatorContext.isActive()) throw notInSimulator("bbFieldMul");
        return new Bigint(MockCrypto.bbFieldMul(a.value(), b.value()));
    }
    public static Bigint bbFieldInv(Bigint a) {
        if (!SimulatorContext.isActive()) throw notInSimulator("bbFieldInv");
        return new Bigint(MockCrypto.bbFieldInv(a.value()));
    }

    // ===================================================================
    // Baby Bear Ext4 (quartic extension field) arithmetic — Go-only crypto
    // family. The Rúnar Java compiler recognises these names as builtins
    // (returning {@code bigint}) but no off-chain simulator implementation
    // ships in {@link MockCrypto} yet. The shims are present so contracts
    // referencing them parse + Java-compile; calling them at JVM runtime
    // throws {@link UnsupportedOperationException}.
    // ===================================================================

    public static Bigint bbExt4Mul0(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                    Bigint b0, Bigint b1, Bigint b2, Bigint b3) {
        throw notInSimulator("bbExt4Mul0");
    }
    public static Bigint bbExt4Mul1(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                    Bigint b0, Bigint b1, Bigint b2, Bigint b3) {
        throw notInSimulator("bbExt4Mul1");
    }
    public static Bigint bbExt4Mul2(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                    Bigint b0, Bigint b1, Bigint b2, Bigint b3) {
        throw notInSimulator("bbExt4Mul2");
    }
    public static Bigint bbExt4Mul3(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                    Bigint b0, Bigint b1, Bigint b2, Bigint b3) {
        throw notInSimulator("bbExt4Mul3");
    }
    public static Bigint bbExt4Inv0(Bigint a0, Bigint a1, Bigint a2, Bigint a3) {
        throw notInSimulator("bbExt4Inv0");
    }
    public static Bigint bbExt4Inv1(Bigint a0, Bigint a1, Bigint a2, Bigint a3) {
        throw notInSimulator("bbExt4Inv1");
    }
    public static Bigint bbExt4Inv2(Bigint a0, Bigint a1, Bigint a2, Bigint a3) {
        throw notInSimulator("bbExt4Inv2");
    }
    public static Bigint bbExt4Inv3(Bigint a0, Bigint a1, Bigint a2, Bigint a3) {
        throw notInSimulator("bbExt4Inv3");
    }

    // ===================================================================
    // Merkle proof verification — SHA-256 (STARK / FRI) and Hash256
    // (Bitcoin). Bigint-typed shims delegate to {@link MockCrypto}.
    // ===================================================================

    public static ByteString merkleRootSha256(ByteString leaf, ByteString proof, Bigint index, Bigint depth) {
        if (!SimulatorContext.isActive()) throw notInSimulator("merkleRootSha256");
        return MockCrypto.merkleRootSha256(leaf, proof, index.value(), depth.value());
    }
    public static ByteString merkleRootHash256(ByteString leaf, ByteString proof, Bigint index, Bigint depth) {
        if (!SimulatorContext.isActive()) throw notInSimulator("merkleRootHash256");
        return MockCrypto.merkleRootHash256(leaf, proof, index.value(), depth.value());
    }
}
