package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import runar.compiler.codegen.Ec.ECTracker;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.NipOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.SwapOp;

/**
 * P-256 / P-384 codegen — NIST elliptic curve operations for Bitcoin Script.
 *
 * <p>Direct port of {@code compilers/go/codegen/p256_p384.go} and
 * {@code compilers/python/runar_compiler/codegen/p256_p384.py}.
 *
 * <p>Point representation:
 * <ul>
 *   <li>P-256: 64 bytes (x[32] || y[32], big-endian unsigned)</li>
 *   <li>P-384: 96 bytes (x[48] || y[48], big-endian unsigned)</li>
 * </ul>
 *
 * <p>Key difference from secp256k1: curve parameter a = -3 (not 0), which
 * gives an optimized Jacobian doubling formula.
 */
public final class P256P384 {

    private P256P384() {}

    // ===================================================================
    // P-256 constants (secp256r1 / NIST P-256)
    // ===================================================================

    public static final BigInteger P256_P = new BigInteger(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    public static final BigInteger P256_P_MINUS_2 = P256_P.subtract(BigInteger.TWO);
    public static final BigInteger P256_B = new BigInteger(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    public static final BigInteger P256_N = new BigInteger(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    public static final BigInteger P256_N_MINUS_2 = P256_N.subtract(BigInteger.TWO);
    public static final BigInteger P256_GX = new BigInteger(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    public static final BigInteger P256_GY = new BigInteger(
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    /** sqrtExp = (p + 1) / 4. */
    public static final BigInteger P256_SQRT_EXP =
        P256_P.add(BigInteger.ONE).shiftRight(2);

    // ===================================================================
    // P-384 constants (secp384r1 / NIST P-384)
    // ===================================================================

    public static final BigInteger P384_P = new BigInteger(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);
    public static final BigInteger P384_P_MINUS_2 = P384_P.subtract(BigInteger.TWO);
    public static final BigInteger P384_B = new BigInteger(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16);
    public static final BigInteger P384_N = new BigInteger(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16);
    public static final BigInteger P384_N_MINUS_2 = P384_N.subtract(BigInteger.TWO);
    public static final BigInteger P384_GX = new BigInteger(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16);
    public static final BigInteger P384_GY = new BigInteger(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16);
    public static final BigInteger P384_SQRT_EXP =
        P384_P.add(BigInteger.ONE).shiftRight(2);

    // ===================================================================
    // Helpers
    // ===================================================================

    /** Convert a non-negative BigInteger to a fixed-width big-endian byte array. */
    private static byte[] bigintToNBytes(BigInteger n, int size) {
        byte[] src = n.toByteArray();
        byte[] out = new byte[size];
        int copyLen = Math.min(src.length, size);
        int srcOff = src.length > size ? src.length - size : 0;
        int dstOff = size - copyLen;
        System.arraycopy(src, srcOff, out, dstOff, copyLen);
        return out;
    }

    private static int bitLen(BigInteger n) {
        return n.bitLength();
    }

    @FunctionalInterface
    interface ReverseBytesFn {
        void emit(Consumer<StackOp> e);
    }

    /** Inline byte reversal for a 48-byte value on TOS (P-384). */
    static void emitReverse48(Consumer<StackOp> e) {
        e.accept(new OpcodeOp("OP_0"));
        e.accept(new SwapOp());
        for (int i = 0; i < 48; i++) {
            e.accept(new PushOp(PushValue.of(1)));
            e.accept(new OpcodeOp("OP_SPLIT"));
            e.accept(new RotOp());
            e.accept(new RotOp());
            e.accept(new SwapOp());
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new SwapOp());
        }
        e.accept(new DropOp());
    }

    private static final ReverseBytesFn REV32 = Ec::emitReverse32;
    private static final ReverseBytesFn REV48 = P256P384::emitReverse48;

    // ===================================================================
    // Field arithmetic (mod p)
    // ===================================================================

    private static void cPushFieldP(ECTracker t, String name, BigInteger fieldP) {
        t.pushBigInt(name, fieldP);
    }

    private static void cFieldMod(ECTracker t, String aName, String resultName, BigInteger fieldP) {
        t.toTop(aName);
        cPushFieldP(t, "_fmod_p", fieldP);
        t.rawBlock(List.of(aName, "_fmod_p"), resultName, e -> {
            e.accept(new OpcodeOp("OP_2DUP"));
            e.accept(new OpcodeOp("OP_MOD"));
            e.accept(new RotOp());
            e.accept(new DropOp());
            e.accept(new OverOp());
            e.accept(new OpcodeOp("OP_ADD"));
            e.accept(new SwapOp());
            e.accept(new OpcodeOp("OP_MOD"));
        });
    }

    private static void cFieldAdd(ECTracker t, String aName, String bName, String resultName, BigInteger fieldP) {
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fadd_sum",
            e -> e.accept(new OpcodeOp("OP_ADD")));
        cFieldMod(t, "_fadd_sum", resultName, fieldP);
    }

    private static void cFieldSub(ECTracker t, String aName, String bName, String resultName, BigInteger fieldP) {
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fsub_diff",
            e -> e.accept(new OpcodeOp("OP_SUB")));
        cFieldMod(t, "_fsub_diff", resultName, fieldP);
    }

    private static void cFieldMul(ECTracker t, String aName, String bName, String resultName, BigInteger fieldP) {
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fmul_prod",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        cFieldMod(t, "_fmul_prod", resultName, fieldP);
    }

    private static void cFieldMulConst(ECTracker t, String aName, long cv, String resultName, BigInteger fieldP) {
        t.toTop(aName);
        t.rawBlock(List.of(aName), "_fmc_prod", e -> {
            if (cv == 2L) {
                e.accept(new OpcodeOp("OP_2MUL"));
            } else {
                e.accept(new PushOp(PushValue.of(cv)));
                e.accept(new OpcodeOp("OP_MUL"));
            }
        });
        cFieldMod(t, "_fmc_prod", resultName, fieldP);
    }

    private static void cFieldSqr(ECTracker t, String aName, String resultName, BigInteger fieldP) {
        t.copyToTop(aName, "_fsqr_copy");
        cFieldMul(t, aName, "_fsqr_copy", resultName, fieldP);
    }

    /** Compute a^(p-2) mod p via generic square-and-multiply. */
    private static void cFieldInv(ECTracker t, String aName, String resultName,
                                  BigInteger fieldP, BigInteger pMinus2) {
        int bits = bitLen(pMinus2);

        // Start: result = a (highest bit of exp is 1)
        t.copyToTop(aName, "_inv_r");

        for (int i = bits - 2; i >= 0; i--) {
            cFieldSqr(t, "_inv_r", "_inv_r2", fieldP);
            t.rename("_inv_r");
            if (pMinus2.testBit(i)) {
                t.copyToTop(aName, "_inv_a");
                cFieldMul(t, "_inv_r", "_inv_a", "_inv_m", fieldP);
                t.rename("_inv_r");
            }
        }

        t.toTop(aName);
        t.drop();
        t.toTop("_inv_r");
        t.rename(resultName);
    }

    // ===================================================================
    // Group-order arithmetic (mod n, for ECDSA)
    // ===================================================================

    private static void cPushGroupN(ECTracker t, String name, BigInteger n) {
        t.pushBigInt(name, n);
    }

    private static void cGroupMod(ECTracker t, String aName, String resultName, BigInteger n) {
        t.toTop(aName);
        cPushGroupN(t, "_gmod_n", n);
        t.rawBlock(List.of(aName, "_gmod_n"), resultName, e -> {
            e.accept(new OpcodeOp("OP_2DUP"));
            e.accept(new OpcodeOp("OP_MOD"));
            e.accept(new RotOp());
            e.accept(new DropOp());
            e.accept(new OverOp());
            e.accept(new OpcodeOp("OP_ADD"));
            e.accept(new SwapOp());
            e.accept(new OpcodeOp("OP_MOD"));
        });
    }

    private static void cGroupMul(ECTracker t, String aName, String bName, String resultName, BigInteger n) {
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_gmul_prod",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        cGroupMod(t, "_gmul_prod", resultName, n);
    }

    /** Compute a^(n-2) mod n via square-and-multiply. */
    private static void cGroupInv(ECTracker t, String aName, String resultName,
                                  BigInteger n, BigInteger nMinus2) {
        int bits = bitLen(nMinus2);

        t.copyToTop(aName, "_ginv_r");

        for (int i = bits - 2; i >= 0; i--) {
            // Square via copy + multiply (mirrors Go reference exactly).
            t.copyToTop("_ginv_r", "_ginv_sq_copy");
            cGroupMul(t, "_ginv_r", "_ginv_sq_copy", "_ginv_sq", n);
            t.rename("_ginv_r");
            if (nMinus2.testBit(i)) {
                t.copyToTop(aName, "_ginv_a");
                cGroupMul(t, "_ginv_r", "_ginv_a", "_ginv_m", n);
                t.rename("_ginv_r");
            }
        }

        t.toTop(aName);
        t.drop();
        t.toTop("_ginv_r");
        t.rename(resultName);
    }

    // ===================================================================
    // Point decompose / compose (parameterized by coord byte size)
    // ===================================================================

    private static void cDecomposePoint(ECTracker t, String pointName,
                                        String xName, String yName,
                                        int coordBytes, ReverseBytesFn revFn) {
        t.toTop(pointName);
        t.rawBlock(List.of(pointName), "", e -> {
            e.accept(new PushOp(PushValue.of(coordBytes)));
            e.accept(new OpcodeOp("OP_SPLIT"));
        });
        t.nm.add("_dp_xb");
        t.nm.add("_dp_yb");

        // Convert y_bytes (on top) to num
        t.rawBlock(List.of("_dp_yb"), yName, e -> {
            revFn.emit(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });

        // Convert x_bytes to num
        t.toTop("_dp_xb");
        t.rawBlock(List.of("_dp_xb"), xName, e -> {
            revFn.emit(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });

        // Stack: [yName, xName] -> swap to [xName, yName]
        t.swap();
    }

    private static void cComposePoint(ECTracker t, String xName, String yName,
                                      String resultName, int coordBytes,
                                      ReverseBytesFn revFn) {
        long numBinSize = coordBytes + 1L;

        // x to coordBytes big-endian
        t.toTop(xName);
        t.rawBlock(List.of(xName), "_cp_xb", e -> {
            e.accept(new PushOp(PushValue.of(numBinSize)));
            e.accept(new OpcodeOp("OP_NUM2BIN"));
            e.accept(new PushOp(PushValue.of(coordBytes)));
            e.accept(new OpcodeOp("OP_SPLIT"));
            e.accept(new DropOp());
            revFn.emit(e);
        });

        // y to coordBytes big-endian
        t.toTop(yName);
        t.rawBlock(List.of(yName), "_cp_yb", e -> {
            e.accept(new PushOp(PushValue.of(numBinSize)));
            e.accept(new OpcodeOp("OP_NUM2BIN"));
            e.accept(new PushOp(PushValue.of(coordBytes)));
            e.accept(new OpcodeOp("OP_SPLIT"));
            e.accept(new DropOp());
            revFn.emit(e);
        });

        // Cat: x_be || y_be
        t.toTop("_cp_xb");
        t.toTop("_cp_yb");
        t.rawBlock(List.of("_cp_xb", "_cp_yb"), resultName,
            e -> e.accept(new OpcodeOp("OP_CAT")));
    }

    // ===================================================================
    // Affine point addition
    // ===================================================================

    private static void cAffineAdd(ECTracker t, BigInteger fieldP, BigInteger pMinus2) {
        // s_num = qy - py
        t.copyToTop("qy", "_qy1");
        t.copyToTop("py", "_py1");
        cFieldSub(t, "_qy1", "_py1", "_s_num", fieldP);

        // s_den = qx - px
        t.copyToTop("qx", "_qx1");
        t.copyToTop("px", "_px1");
        cFieldSub(t, "_qx1", "_px1", "_s_den", fieldP);

        // s = s_num / s_den mod p
        cFieldInv(t, "_s_den", "_s_den_inv", fieldP, pMinus2);
        cFieldMul(t, "_s_num", "_s_den_inv", "_s", fieldP);

        // rx = s^2 - px - qx mod p
        t.copyToTop("_s", "_s_keep");
        cFieldSqr(t, "_s", "_s2", fieldP);
        t.copyToTop("px", "_px2");
        cFieldSub(t, "_s2", "_px2", "_rx1", fieldP);
        t.copyToTop("qx", "_qx2");
        cFieldSub(t, "_rx1", "_qx2", "rx", fieldP);

        // ry = s * (px - rx) - py mod p
        t.copyToTop("px", "_px3");
        t.copyToTop("rx", "_rx2");
        cFieldSub(t, "_px3", "_rx2", "_px_rx", fieldP);
        cFieldMul(t, "_s_keep", "_px_rx", "_s_px_rx", fieldP);
        t.copyToTop("py", "_py2");
        cFieldSub(t, "_s_px_rx", "_py2", "ry", fieldP);

        // Clean up original points
        t.toTop("px"); t.drop();
        t.toTop("py"); t.drop();
        t.toTop("qx"); t.drop();
        t.toTop("qy"); t.drop();
    }

    // ===================================================================
    // Jacobian point doubling (a = -3 optimization)
    // ===================================================================

    private static void cJacobianDouble(ECTracker t, BigInteger fieldP, BigInteger pMinus2) {
        // Z^2
        t.copyToTop("jz", "_jz_sq_tmp");
        cFieldSqr(t, "_jz_sq_tmp", "_Z2", fieldP);

        // X - Z^2 and X + Z^2
        t.copyToTop("jx", "_jx_c1");
        t.copyToTop("_Z2", "_Z2_c1");
        cFieldSub(t, "_jx_c1", "_Z2_c1", "_X_minus_Z2", fieldP);
        t.copyToTop("jx", "_jx_c2");
        cFieldAdd(t, "_jx_c2", "_Z2", "_X_plus_Z2", fieldP);

        // A = 3 * (X - Z^2) * (X + Z^2)
        cFieldMul(t, "_X_minus_Z2", "_X_plus_Z2", "_prod", fieldP);
        t.pushInt("_three", 3);
        cFieldMul(t, "_prod", "_three", "_A", fieldP);

        // B = 4 * X * Y^2
        t.copyToTop("jy", "_jy_sq_tmp");
        cFieldSqr(t, "_jy_sq_tmp", "_Y2", fieldP);
        t.copyToTop("_Y2", "_Y2_c1");
        t.copyToTop("jx", "_jx_c3");
        cFieldMul(t, "_jx_c3", "_Y2", "_xY2", fieldP);
        t.pushInt("_four", 4);
        cFieldMul(t, "_xY2", "_four", "_B", fieldP);

        // C = 8 * Y^4
        cFieldSqr(t, "_Y2_c1", "_Y4", fieldP);
        t.pushInt("_eight", 8);
        cFieldMul(t, "_Y4", "_eight", "_C", fieldP);

        // X3 = A^2 - 2*B
        t.copyToTop("_A", "_A_save");
        t.copyToTop("_B", "_B_save");
        cFieldSqr(t, "_A", "_A2", fieldP);
        t.copyToTop("_B", "_B_c1");
        cFieldMulConst(t, "_B_c1", 2, "_2B", fieldP);
        cFieldSub(t, "_A2", "_2B", "_X3", fieldP);

        // Y3 = A*(B - X3) - C
        t.copyToTop("_X3", "_X3_c");
        cFieldSub(t, "_B_save", "_X3_c", "_B_minus_X3", fieldP);
        cFieldMul(t, "_A_save", "_B_minus_X3", "_A_tmp", fieldP);
        cFieldSub(t, "_A_tmp", "_C", "_Y3", fieldP);

        // Z3 = 2*Y*Z
        t.copyToTop("jy", "_jy_c");
        t.copyToTop("jz", "_jz_c");
        cFieldMul(t, "_jy_c", "_jz_c", "_yz", fieldP);
        cFieldMulConst(t, "_yz", 2, "_Z3", fieldP);

        // Clean up and rename
        t.toTop("_B"); t.drop();
        t.toTop("jz"); t.drop();
        t.toTop("jx"); t.drop();
        t.toTop("jy"); t.drop();
        t.toTop("_X3"); t.rename("jx");
        t.toTop("_Y3"); t.rename("jy");
        t.toTop("_Z3"); t.rename("jz");
    }

    // ===================================================================
    // Jacobian to affine
    // ===================================================================

    private static void cJacobianToAffine(ECTracker t, String rxName, String ryName,
                                          BigInteger fieldP, BigInteger pMinus2) {
        cFieldInv(t, "jz", "_zinv", fieldP, pMinus2);
        t.copyToTop("_zinv", "_zinv_keep");
        cFieldSqr(t, "_zinv", "_zinv2", fieldP);
        t.copyToTop("_zinv2", "_zinv2_keep");
        cFieldMul(t, "_zinv_keep", "_zinv2", "_zinv3", fieldP);
        cFieldMul(t, "jx", "_zinv2_keep", rxName, fieldP);
        cFieldMul(t, "jy", "_zinv3", ryName, fieldP);
    }

    // ===================================================================
    // Jacobian mixed addition (P_jacobian + Q_affine), inline for OP_IF
    // ===================================================================

    private static void cBuildJacobianAddAffineInline(Consumer<StackOp> e, ECTracker t,
                                                       BigInteger fieldP, BigInteger pMinus2) {
        ECTracker it = new ECTracker(t.nm, e);

        it.copyToTop("jz", "_jz_for_z1cu");
        it.copyToTop("jz", "_jz_for_z3");
        it.copyToTop("jy", "_jy_for_y3");
        it.copyToTop("jx", "_jx_for_u1h2");

        // Z1sq = jz^2
        cFieldSqr(it, "jz", "_Z1sq", fieldP);

        // Z1cu = _jz_for_z1cu * Z1sq
        it.copyToTop("_Z1sq", "_Z1sq_for_u2");
        cFieldMul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu", fieldP);

        // U2 = ax * Z1sq_for_u2
        it.copyToTop("ax", "_ax_c");
        cFieldMul(it, "_ax_c", "_Z1sq_for_u2", "_U2", fieldP);

        // S2 = ay * Z1cu
        it.copyToTop("ay", "_ay_c");
        cFieldMul(it, "_ay_c", "_Z1cu", "_S2", fieldP);

        // H = U2 - jx
        cFieldSub(it, "_U2", "jx", "_H", fieldP);

        // R = S2 - jy
        cFieldSub(it, "_S2", "jy", "_R", fieldP);

        it.copyToTop("_H", "_H_for_h3");
        it.copyToTop("_H", "_H_for_z3");

        // H2 = H^2
        cFieldSqr(it, "_H", "_H2", fieldP);

        it.copyToTop("_H2", "_H2_for_u1h2");

        // H3 = H_for_h3 * H2
        cFieldMul(it, "_H_for_h3", "_H2", "_H3", fieldP);

        // U1H2 = _jx_for_u1h2 * H2_for_u1h2
        cFieldMul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2", fieldP);

        it.copyToTop("_R", "_R_for_y3");
        it.copyToTop("_U1H2", "_U1H2_for_y3");
        it.copyToTop("_H3", "_H3_for_y3");

        // X3 = R^2 - H3 - 2*U1H2
        cFieldSqr(it, "_R", "_R2", fieldP);
        cFieldSub(it, "_R2", "_H3", "_x3_tmp", fieldP);
        cFieldMulConst(it, "_U1H2", 2, "_2U1H2", fieldP);
        cFieldSub(it, "_x3_tmp", "_2U1H2", "_X3", fieldP);

        // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
        it.copyToTop("_X3", "_X3_c");
        cFieldSub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x", fieldP);
        cFieldMul(it, "_R_for_y3", "_u_minus_x", "_r_tmp", fieldP);
        cFieldMul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3", fieldP);
        cFieldSub(it, "_r_tmp", "_jy_h3", "_Y3", fieldP);

        // Z3 = _jz_for_z3 * _H_for_z3
        cFieldMul(it, "_jz_for_z3", "_H_for_z3", "_Z3", fieldP);

        it.toTop("_X3"); it.rename("jx");
        it.toTop("_Y3"); it.rename("jy");
        it.toTop("_Z3"); it.rename("jz");
    }

    // ===================================================================
    // Scalar multiplication (generic for both P-256 and P-384)
    // ===================================================================

    private static void cEmitMul(Consumer<StackOp> emit, int coordBytes,
                                  ReverseBytesFn revFn, BigInteger fieldP,
                                  BigInteger pMinus2, BigInteger curveN, BigInteger nMinus2) {
        ECTracker t = new ECTracker(List.of("_pt", "_k"), emit);
        cDecomposePoint(t, "_pt", "ax", "ay", coordBytes, revFn);

        // k' = k + 3n (three separate adds, matches Go reference)
        t.toTop("_k");
        t.pushBigInt("_n", curveN);
        t.rawBlock(List.of("_k", "_n"), "_kn",
            e -> e.accept(new OpcodeOp("OP_ADD")));
        t.pushBigInt("_n2", curveN);
        t.rawBlock(List.of("_kn", "_n2"), "_kn2",
            e -> e.accept(new OpcodeOp("OP_ADD")));
        t.pushBigInt("_n3", curveN);
        t.rawBlock(List.of("_kn2", "_n3"), "_kn3",
            e -> e.accept(new OpcodeOp("OP_ADD")));
        t.rename("_k");

        // Iteration count: bits of (4n - 1), highest bit always 1 → start one below.
        BigInteger fourNMinus1 = curveN.multiply(BigInteger.valueOf(4)).subtract(BigInteger.ONE);
        int topBit = bitLen(fourNMinus1);
        int startBit = topBit - 2;

        // Init accumulator = P
        t.copyToTop("ax", "jx");
        t.copyToTop("ay", "jy");
        t.pushInt("jz", 1);

        for (int bit = startBit; bit >= 0; bit--) {
            cJacobianDouble(t, fieldP, pMinus2);

            // Extract bit: (k >> bit) & 1
            t.copyToTop("_k", "_k_copy");
            if (bit == 1) {
                t.rawBlock(List.of("_k_copy"), "_shifted",
                    e -> e.accept(new OpcodeOp("OP_2DIV")));
            } else if (bit > 1) {
                t.pushInt("_shift", bit);
                t.rawBlock(List.of("_k_copy", "_shift"), "_shifted",
                    e -> e.accept(new OpcodeOp("OP_RSHIFTNUM")));
            } else {
                t.rename("_shifted");
            }
            t.pushInt("_two", 2);
            t.rawBlock(List.of("_shifted", "_two"), "_bit",
                e -> e.accept(new OpcodeOp("OP_MOD")));

            // Conditional add
            t.toTop("_bit");
            t.nm.remove(t.nm.size() - 1); // _bit consumed by IF
            List<StackOp> addOps = new ArrayList<>();
            cBuildJacobianAddAffineInline(addOps::add, t, fieldP, pMinus2);
            emit.accept(new IfOp(addOps, List.of()));
        }

        cJacobianToAffine(t, "_rx", "_ry", fieldP, pMinus2);

        // Clean up base point + scalar
        t.toTop("ax"); t.drop();
        t.toTop("ay"); t.drop();
        t.toTop("_k"); t.drop();

        cComposePoint(t, "_rx", "_ry", "_result", coordBytes, revFn);
    }

    // ===================================================================
    // Square-and-multiply modular exponentiation (for sqrt)
    // ===================================================================

    private static void cFieldPow(ECTracker t, String baseName, BigInteger exp,
                                   String resultName, BigInteger fieldP, BigInteger pMinus2) {
        int bits = bitLen(exp);

        t.copyToTop(baseName, "_pow_r");

        for (int i = bits - 2; i >= 0; i--) {
            cFieldSqr(t, "_pow_r", "_pow_sq", fieldP);
            t.rename("_pow_r");
            if (exp.testBit(i)) {
                t.copyToTop(baseName, "_pow_b");
                cFieldMul(t, "_pow_r", "_pow_b", "_pow_m", fieldP);
                t.rename("_pow_r");
            }
        }

        t.toTop(baseName);
        t.drop();
        t.toTop("_pow_r");
        t.rename(resultName);
    }

    // ===================================================================
    // Pubkey decompression (prefix byte + x → (x, y))
    // ===================================================================

    private static void cDecompressPubKey(ECTracker t, String pkName, String qxName,
                                           String qyName, int coordBytes,
                                           ReverseBytesFn revFn, BigInteger fieldP,
                                           BigInteger pMinus2, BigInteger curveB,
                                           BigInteger sqrtExp) {
        t.toTop(pkName);

        // Split: [prefix_byte, x_bytes]
        t.rawBlock(List.of(pkName), "", e -> {
            e.accept(new PushOp(PushValue.of(1)));
            e.accept(new OpcodeOp("OP_SPLIT"));
        });
        t.nm.add("_dk_prefix");
        t.nm.add("_dk_xbytes");

        // Convert prefix to parity: 0x02 → 0, 0x03 → 1
        t.toTop("_dk_prefix");
        t.rawBlock(List.of("_dk_prefix"), "_dk_parity", e -> {
            e.accept(new OpcodeOp("OP_BIN2NUM"));
            e.accept(new PushOp(PushValue.of(2)));
            e.accept(new OpcodeOp("OP_MOD"));
        });

        // Stash parity on altstack
        t.toTop("_dk_parity");
        t.toAlt();

        // Convert x_bytes to number
        t.toTop("_dk_xbytes");
        t.rawBlock(List.of("_dk_xbytes"), "_dk_x", e -> {
            revFn.emit(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });

        // Save x for later
        t.copyToTop("_dk_x", "_dk_x_save");

        // Compute y^2 = x^3 - 3x + b mod p
        t.copyToTop("_dk_x", "_dk_x_c1");
        cFieldSqr(t, "_dk_x", "_dk_x2", fieldP);
        cFieldMul(t, "_dk_x2", "_dk_x_c1", "_dk_x3", fieldP);
        t.copyToTop("_dk_x_save", "_dk_x_for_3");
        cFieldMulConst(t, "_dk_x_for_3", 3, "_dk_3x", fieldP);
        cFieldSub(t, "_dk_x3", "_dk_3x", "_dk_x3m3x", fieldP);
        t.pushBigInt("_dk_b", curveB);
        cFieldAdd(t, "_dk_x3m3x", "_dk_b", "_dk_y2", fieldP);

        // y = (y^2)^sqrtExp mod p
        cFieldPow(t, "_dk_y2", sqrtExp, "_dk_y_cand", fieldP, pMinus2);

        // Check candidate y parity
        t.copyToTop("_dk_y_cand", "_dk_y_check");
        t.rawBlock(List.of("_dk_y_check"), "_dk_y_par", e -> {
            e.accept(new PushOp(PushValue.of(2)));
            e.accept(new OpcodeOp("OP_MOD"));
        });

        // Retrieve parity from altstack
        t.fromAlt("_dk_parity");

        // Compare
        t.toTop("_dk_y_par");
        t.toTop("_dk_parity");
        t.rawBlock(List.of("_dk_y_par", "_dk_parity"), "_dk_match",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));

        // Compute p - y_cand
        t.copyToTop("_dk_y_cand", "_dk_y_for_neg");
        cPushFieldP(t, "_dk_pfn", fieldP);
        t.toTop("_dk_y_for_neg");
        t.rawBlock(List.of("_dk_pfn", "_dk_y_for_neg"), "_dk_neg_y",
            e -> e.accept(new OpcodeOp("OP_SUB")));

        // OP_IF select: match → use y_cand (drop neg_y), else → use neg_y (nip y_cand)
        t.toTop("_dk_match");
        t.nm.remove(t.nm.size() - 1); // condition consumed by IF

        List<StackOp> thenOps = List.of(new DropOp());
        List<StackOp> elseOps = List.of(new NipOp());
        t.e.accept(new IfOp(thenOps, elseOps));

        // Remove _dk_neg_y from tracker (one of the two was consumed)
        for (int i = t.nm.size() - 1; i >= 0; i--) {
            if ("_dk_neg_y".equals(t.nm.get(i))) {
                t.nm.remove(i);
                break;
            }
        }
        // Rename y_cand to qy_name
        for (int i = t.nm.size() - 1; i >= 0; i--) {
            if ("_dk_y_cand".equals(t.nm.get(i))) {
                t.nm.set(i, qyName);
                break;
            }
        }
        // Rename x_save to qx_name
        for (int i = t.nm.size() - 1; i >= 0; i--) {
            if ("_dk_x_save".equals(t.nm.get(i))) {
                t.nm.set(i, qxName);
                break;
            }
        }
    }

    // ===================================================================
    // ECDSA verification (generic)
    // ===================================================================

    private static void cEmitVerifyECDSA(Consumer<StackOp> emit, int coordBytes,
                                         ReverseBytesFn revFn, BigInteger fieldP,
                                         BigInteger pMinus2, BigInteger curveN,
                                         BigInteger nMinus2, BigInteger curveB,
                                         BigInteger sqrtExp, BigInteger gx, BigInteger gy) {
        ECTracker t = new ECTracker(List.of("_msg", "_sig", "_pk"), emit);

        // Step 1: e = SHA-256(msg) as integer
        t.toTop("_msg");
        t.rawBlock(List.of("_msg"), "_e", e -> {
            e.accept(new OpcodeOp("OP_SHA256"));
            Ec.emitReverse32(e); // SHA-256 output is always 32 bytes
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });

        // Step 2: Parse sig into (r, s)
        t.toTop("_sig");
        t.rawBlock(List.of("_sig"), "", e -> {
            e.accept(new PushOp(PushValue.of(coordBytes)));
            e.accept(new OpcodeOp("OP_SPLIT"));
        });
        t.nm.add("_r_bytes");
        t.nm.add("_s_bytes");

        // r_bytes → integer
        t.toTop("_r_bytes");
        t.rawBlock(List.of("_r_bytes"), "_r", e -> {
            revFn.emit(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });

        // s_bytes → integer
        t.toTop("_s_bytes");
        t.rawBlock(List.of("_s_bytes"), "_s", e -> {
            revFn.emit(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });

        // Step 3: Decompress pubkey
        cDecompressPubKey(t, "_pk", "_qx", "_qy",
            coordBytes, revFn, fieldP, pMinus2, curveB, sqrtExp);

        // Step 4: w = s^{-1} mod n
        cGroupInv(t, "_s", "_w", curveN, nMinus2);

        // Step 5: u1 = e * w mod n
        t.copyToTop("_w", "_w_c1");
        cGroupMul(t, "_e", "_w_c1", "_u1", curveN);

        // Step 6: u2 = r * w mod n
        t.copyToTop("_r", "_r_save");
        cGroupMul(t, "_r", "_w", "_u2", curveN);

        // Step 7: R = u1*G + u2*Q
        byte[] gPointData = new byte[coordBytes * 2];
        System.arraycopy(bigintToNBytes(gx, coordBytes), 0, gPointData, 0, coordBytes);
        System.arraycopy(bigintToNBytes(gy, coordBytes), 0, gPointData, coordBytes, coordBytes);

        t.pushBytes("_G", gPointData);
        t.toTop("_u1");

        // Stash items on altstack
        t.toTop("_r_save"); t.toAlt();
        t.toTop("_u2");     t.toAlt();
        t.toTop("_qy");     t.toAlt();
        t.toTop("_qx");     t.toAlt();

        // Remove _G and _u1 from tracker before cEmitMul
        t.nm.remove(t.nm.size() - 1); // _u1
        t.nm.remove(t.nm.size() - 1); // _G

        cEmitMul(emit, coordBytes, revFn, fieldP, pMinus2, curveN, nMinus2);

        // After mul, one result point is on the stack
        t.nm.add("_R1_point");

        // Pop qx/qy/u2 from altstack (LIFO)
        t.fromAlt("_qx");
        t.fromAlt("_qy");
        t.fromAlt("_u2");

        // Stash R1 point
        t.toTop("_R1_point"); t.toAlt();

        // Compose Q point
        cComposePoint(t, "_qx", "_qy", "_Q_point", coordBytes, revFn);

        t.toTop("_u2");

        // Remove from tracker, emit mul, push result
        t.nm.remove(t.nm.size() - 1); // _u2
        t.nm.remove(t.nm.size() - 1); // _Q_point
        cEmitMul(emit, coordBytes, revFn, fieldP, pMinus2, curveN, nMinus2);
        t.nm.add("_R2_point");

        // Restore R1 point
        t.fromAlt("_R1_point");

        // Swap so R2 is on top
        t.swap();

        // Decompose both, add, compose
        cDecomposePoint(t, "_R1_point", "_rpx", "_rpy", coordBytes, revFn);
        cDecomposePoint(t, "_R2_point", "_rqx", "_rqy", coordBytes, revFn);

        // Rename to what cAffineAdd expects
        for (int i = t.nm.size() - 1; i >= 0; i--) {
            if ("_rpx".equals(t.nm.get(i))) { t.nm.set(i, "px"); break; }
        }
        for (int i = t.nm.size() - 1; i >= 0; i--) {
            if ("_rpy".equals(t.nm.get(i))) { t.nm.set(i, "py"); break; }
        }
        for (int i = t.nm.size() - 1; i >= 0; i--) {
            if ("_rqx".equals(t.nm.get(i))) { t.nm.set(i, "qx"); break; }
        }
        for (int i = t.nm.size() - 1; i >= 0; i--) {
            if ("_rqy".equals(t.nm.get(i))) { t.nm.set(i, "qy"); break; }
        }

        cAffineAdd(t, fieldP, pMinus2);

        // Step 8: x_R mod n == r
        t.toTop("ry"); t.drop();

        cGroupMod(t, "rx", "_rx_mod_n", curveN);

        // Restore r
        t.fromAlt("_r_save");

        // Compare
        t.toTop("_rx_mod_n");
        t.toTop("_r_save");
        t.rawBlock(List.of("_rx_mod_n", "_r_save"), "_result",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));
    }

    // ===================================================================
    // P-256 public API
    // ===================================================================

    public static void emitP256Add(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pa", "_pb"), emit);
        cDecomposePoint(t, "_pa", "px", "py", 32, REV32);
        cDecomposePoint(t, "_pb", "qx", "qy", 32, REV32);
        cAffineAdd(t, P256_P, P256_P_MINUS_2);
        cComposePoint(t, "rx", "ry", "_result", 32, REV32);
    }

    public static void emitP256Mul(Consumer<StackOp> emit) {
        cEmitMul(emit, 32, REV32, P256_P, P256_P_MINUS_2, P256_N, P256_N_MINUS_2);
    }

    public static void emitP256MulGen(Consumer<StackOp> emit) {
        byte[] gPoint = new byte[64];
        System.arraycopy(bigintToNBytes(P256_GX, 32), 0, gPoint, 0, 32);
        System.arraycopy(bigintToNBytes(P256_GY, 32), 0, gPoint, 32, 32);
        emit.accept(new PushOp(PushValue.ofHex(Ec.hexOf(gPoint))));
        emit.accept(new SwapOp()); // [point, scalar]
        emitP256Mul(emit);
    }

    public static void emitP256Negate(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pt"), emit);
        cDecomposePoint(t, "_pt", "_nx", "_ny", 32, REV32);
        cPushFieldP(t, "_fp", P256_P);
        cFieldSub(t, "_fp", "_ny", "_neg_y", P256_P);
        cComposePoint(t, "_nx", "_neg_y", "_result", 32, REV32);
    }

    public static void emitP256OnCurve(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pt"), emit);
        cDecomposePoint(t, "_pt", "_x", "_y", 32, REV32);

        // lhs = y^2
        cFieldSqr(t, "_y", "_y2", P256_P);

        // rhs = x^3 - 3x + b
        t.copyToTop("_x", "_x_copy");
        t.copyToTop("_x", "_x_copy2");
        cFieldSqr(t, "_x", "_x2", P256_P);
        cFieldMul(t, "_x2", "_x_copy", "_x3", P256_P);
        cFieldMulConst(t, "_x_copy2", 3, "_3x", P256_P);
        cFieldSub(t, "_x3", "_3x", "_x3m3x", P256_P);
        t.pushBigInt("_b", P256_B);
        cFieldAdd(t, "_x3m3x", "_b", "_rhs", P256_P);

        t.toTop("_y2");
        t.toTop("_rhs");
        t.rawBlock(List.of("_y2", "_rhs"), "_result",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));
    }

    public static void emitP256EncodeCompressed(Consumer<StackOp> emit) {
        // Split at 32: [x_bytes, y_bytes]
        emit.accept(new PushOp(PushValue.of(32)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        // Last byte of y for parity
        emit.accept(new OpcodeOp("OP_SIZE"));
        emit.accept(new PushOp(PushValue.of(1)));
        emit.accept(new OpcodeOp("OP_SUB"));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
        emit.accept(new PushOp(PushValue.of(2)));
        emit.accept(new OpcodeOp("OP_MOD"));
        // Stack: [x_bytes, y_prefix, parity]
        emit.accept(new SwapOp());
        emit.accept(new DropOp());
        // Stack: [x_bytes, parity]
        emit.accept(new IfOp(
            List.of(new PushOp(PushValue.ofHex("03"))),
            List.of(new PushOp(PushValue.ofHex("02")))));
        // Stack: [x_bytes, prefix_byte]
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_CAT"));
    }

    public static void emitVerifyECDSA_P256(Consumer<StackOp> emit) {
        cEmitVerifyECDSA(emit, 32, REV32,
            P256_P, P256_P_MINUS_2, P256_N, P256_N_MINUS_2,
            P256_B, P256_SQRT_EXP, P256_GX, P256_GY);
    }

    // ===================================================================
    // P-384 public API
    // ===================================================================

    public static void emitP384Add(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pa", "_pb"), emit);
        cDecomposePoint(t, "_pa", "px", "py", 48, REV48);
        cDecomposePoint(t, "_pb", "qx", "qy", 48, REV48);
        cAffineAdd(t, P384_P, P384_P_MINUS_2);
        cComposePoint(t, "rx", "ry", "_result", 48, REV48);
    }

    public static void emitP384Mul(Consumer<StackOp> emit) {
        cEmitMul(emit, 48, REV48, P384_P, P384_P_MINUS_2, P384_N, P384_N_MINUS_2);
    }

    public static void emitP384MulGen(Consumer<StackOp> emit) {
        byte[] gPoint = new byte[96];
        System.arraycopy(bigintToNBytes(P384_GX, 48), 0, gPoint, 0, 48);
        System.arraycopy(bigintToNBytes(P384_GY, 48), 0, gPoint, 48, 48);
        emit.accept(new PushOp(PushValue.ofHex(Ec.hexOf(gPoint))));
        emit.accept(new SwapOp()); // [point, scalar]
        emitP384Mul(emit);
    }

    public static void emitP384Negate(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pt"), emit);
        cDecomposePoint(t, "_pt", "_nx", "_ny", 48, REV48);
        cPushFieldP(t, "_fp", P384_P);
        cFieldSub(t, "_fp", "_ny", "_neg_y", P384_P);
        cComposePoint(t, "_nx", "_neg_y", "_result", 48, REV48);
    }

    public static void emitP384OnCurve(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pt"), emit);
        cDecomposePoint(t, "_pt", "_x", "_y", 48, REV48);

        cFieldSqr(t, "_y", "_y2", P384_P);

        t.copyToTop("_x", "_x_copy");
        t.copyToTop("_x", "_x_copy2");
        cFieldSqr(t, "_x", "_x2", P384_P);
        cFieldMul(t, "_x2", "_x_copy", "_x3", P384_P);
        cFieldMulConst(t, "_x_copy2", 3, "_3x", P384_P);
        cFieldSub(t, "_x3", "_3x", "_x3m3x", P384_P);
        t.pushBigInt("_b", P384_B);
        cFieldAdd(t, "_x3m3x", "_b", "_rhs", P384_P);

        t.toTop("_y2");
        t.toTop("_rhs");
        t.rawBlock(List.of("_y2", "_rhs"), "_result",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));
    }

    public static void emitP384EncodeCompressed(Consumer<StackOp> emit) {
        emit.accept(new PushOp(PushValue.of(48)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new OpcodeOp("OP_SIZE"));
        emit.accept(new PushOp(PushValue.of(1)));
        emit.accept(new OpcodeOp("OP_SUB"));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
        emit.accept(new PushOp(PushValue.of(2)));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new SwapOp());
        emit.accept(new DropOp());
        emit.accept(new IfOp(
            List.of(new PushOp(PushValue.ofHex("03"))),
            List.of(new PushOp(PushValue.ofHex("02")))));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_CAT"));
    }

    public static void emitVerifyECDSA_P384(Consumer<StackOp> emit) {
        cEmitVerifyECDSA(emit, 48, REV48,
            P384_P, P384_P_MINUS_2, P384_N, P384_N_MINUS_2,
            P384_B, P384_SQRT_EXP, P384_GX, P384_GY);
    }

    // ===================================================================
    // Dispatch
    // ===================================================================

    private static final java.util.Set<String> NIST_NAMES = java.util.Set.of(
        "p256Add", "p256Mul", "p256MulGen",
        "p256Negate", "p256OnCurve", "p256EncodeCompressed",
        "p384Add", "p384Mul", "p384MulGen",
        "p384Negate", "p384OnCurve", "p384EncodeCompressed"
    );

    private static final java.util.Set<String> VERIFY_NAMES = java.util.Set.of(
        "verifyECDSA_P256", "verifyECDSA_P384"
    );

    public static boolean isNistEcBuiltin(String name) {
        return NIST_NAMES.contains(name);
    }

    public static boolean isVerifyEcdsaBuiltin(String name) {
        return VERIFY_NAMES.contains(name);
    }

    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        switch (funcName) {
            case "p256Add" -> emitP256Add(emit);
            case "p256Mul" -> emitP256Mul(emit);
            case "p256MulGen" -> emitP256MulGen(emit);
            case "p256Negate" -> emitP256Negate(emit);
            case "p256OnCurve" -> emitP256OnCurve(emit);
            case "p256EncodeCompressed" -> emitP256EncodeCompressed(emit);
            case "p384Add" -> emitP384Add(emit);
            case "p384Mul" -> emitP384Mul(emit);
            case "p384MulGen" -> emitP384MulGen(emit);
            case "p384Negate" -> emitP384Negate(emit);
            case "p384OnCurve" -> emitP384OnCurve(emit);
            case "p384EncodeCompressed" -> emitP384EncodeCompressed(emit);
            case "verifyECDSA_P256" -> emitVerifyECDSA_P256(emit);
            case "verifyECDSA_P384" -> emitVerifyECDSA_P384(emit);
            default -> throw new RuntimeException("unknown NIST EC builtin: " + funcName);
        }
    }
}
