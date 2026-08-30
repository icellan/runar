package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import runar.compiler.codegen.Ec.ECTracker;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
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
        t.pushConst(Ec.POOL_FIELD_P, fieldP, name);
    }

    /**
     * {@code a mod p} with no sign fix-up: 1 opcode instead of 7. Sound only when the dividend is
     * provably &gt;= 0 — the caller proves that, this does not check.
     */
    private static void cFieldModShort(ECTracker t, String aName, String resultName,
                                       BigInteger fieldP) {
        t.toTop(aName);
        cPushFieldP(t, "_fmods_p", fieldP);
        t.rawBlock(List.of(aName, "_fmods_p"), resultName,
            e -> e.accept(new OpcodeOp("OP_MOD")));
        t.setDomain(resultName, Ec.Dom.REDUCED);
    }

    /** Does the cheap {@code a - b + p} subtraction pay? Only when p is pooled. */
    private static boolean cCheapSubPays(ECTracker t, BigInteger fieldP) {
        int cost = t.constCost(Ec.POOL_FIELD_P, fieldP);
        return 2 * cost + 2 < cost + 8;
    }

    private static void cFieldMod(ECTracker t, String aName, String resultName, BigInteger fieldP) {
        if (t.sinking && t.domainOf(aName).isNonNegative()) {
            cFieldModShort(t, aName, resultName, fieldP);
            return;
        }
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
        t.setDomain(resultName, Ec.Dom.REDUCED);
    }

    private static void cFieldAdd(ECTracker t, String aName, String bName, String resultName, BigInteger fieldP) {
        // Read the operand facts before rawBlock consumes their slots.
        boolean sumNonNeg =
                t.domainOf(aName).isNonNegative() && t.domainOf(bName).isNonNegative();
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fadd_sum",
            e -> e.accept(new OpcodeOp("OP_ADD")));
        if (sumNonNeg) t.setDomain("_fadd_sum", Ec.Dom.NON_NEGATIVE);
        cFieldMod(t, "_fadd_sum", resultName, fieldP);
    }

    private static void cFieldSub(ECTracker t, String aName, String bName, String resultName, BigInteger fieldP) {
        t.toTop(aName);
        t.toTop(bName);
        // Needs a >= 0 AND b in [0, p): then a - b > -p and one shifted
        // reduction is exact. `b >= 0` alone is not enough — a coordinate
        // decoded from 32 unsigned bytes may exceed p by up to 2^32 + 977.
        boolean cheap =
                t.sinking
                        && t.domainOf(aName).isNonNegative()
                        && t.domainOf(bName) == Ec.Dom.REDUCED
                        && cCheapSubPays(t, fieldP);

        t.rawBlock(List.of(aName, bName), "_fsub_diff",
            e -> e.accept(new OpcodeOp("OP_SUB")));

        if (cheap) {
            cPushFieldP(t, "_fsub_p", fieldP);
            t.rawBlock(List.of("_fsub_diff", "_fsub_p"), "_fsub_shift",
                e -> e.accept(new OpcodeOp("OP_ADD")));
            t.setDomain("_fsub_shift", Ec.Dom.NON_NEGATIVE);
            cFieldModShort(t, "_fsub_shift", resultName, fieldP);
            return;
        }
        cFieldMod(t, "_fsub_diff", resultName, fieldP);
    }

    private static void cFieldMul(ECTracker t, String aName, String bName, String resultName, BigInteger fieldP) {
        cFieldMul(t, aName, bName, resultName, fieldP, false);
    }

    /**
     * {@code cFieldMul} with an explicit assertion about the product's sign, independent of the
     * operands: a*a &gt;= 0 for any a whatsoever.
     */
    private static void cFieldMul(ECTracker t, String aName, String bName, String resultName,
                                  BigInteger fieldP, boolean productNonNegative) {
        boolean nonNeg =
                productNonNegative
                        || (t.domainOf(aName).isNonNegative()
                                && t.domainOf(bName).isNonNegative());
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fmul_prod",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        if (nonNeg) t.setDomain("_fmul_prod", Ec.Dom.NON_NEGATIVE);
        cFieldMod(t, "_fmul_prod", resultName, fieldP);
    }

    private static void cFieldMulConst(ECTracker t, String aName, long cv, String resultName, BigInteger fieldP) {
        // Every call site passes a small positive cv, so the product keeps a's sign.
        boolean nonNeg = cv > 0 && t.domainOf(aName).isNonNegative();
        t.toTop(aName);
        t.rawBlock(List.of(aName), "_fmc_prod", e -> {
            if (cv == 2L) {
                e.accept(new OpcodeOp("OP_2MUL"));
            } else {
                e.accept(new PushOp(PushValue.of(cv)));
                e.accept(new OpcodeOp("OP_MUL"));
            }
        });
        if (nonNeg) t.setDomain("_fmc_prod", Ec.Dom.NON_NEGATIVE);
        cFieldMod(t, "_fmc_prod", resultName, fieldP);
    }

    private static void cFieldSqr(ECTracker t, String aName, String resultName, BigInteger fieldP) {
        t.copyToTop(aName, "_fsqr_copy");
        cFieldMul(t, aName, "_fsqr_copy", resultName, fieldP, true);
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
        t.pushConst(Ec.POOL_GROUP_N, n, name);
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

    /**
     * Reduces a scalar to [0, n-1]: ((k mod n) + n) mod n.
     *
     * <p>OP_MOD takes the sign of the DIVIDEND, so {@code k mod n} alone lands in
     * (-n, n); the {@code + n, mod n} normalises the negative half. One push of n
     * covers both reductions — the same shape as {@code emitEcModReduce}.
     *
     * <p>Without it, {@code cEmitMul}'s ladder is only correct while
     * 2^b &lt;= k + 3n &lt; 2^(b+1) for the fixed b it unrolls: a scalar &gt;= ~n
     * sets a bit above the loop's top, the loop never sees it, and the ladder
     * returns a DIFFERENT multiple of P rather than failing. Scalars are contract
     * input, so that is attacker-chosen. Reducing costs 1 push + 8 opcodes
     * (42 / 58 bytes) against a ~460 KB / 1.6 MB script, and makes k &gt;= n,
     * k &lt; 0 and k = 0 all well defined.
     */
    private static void cEmitScalarReduce(ECTracker t, String kName, String resultName, BigInteger n) {
        cPushGroupN(t, "_n_red", n);
        t.rawBlock(List.of(kName, "_n_red"), resultName, e -> {
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
        t.pushTracked("_dp_xb", Ec.Dom.UNKNOWN);
        t.pushTracked("_dp_yb", Ec.Dom.UNKNOWN);

        // Convert y_bytes (on top) to num
        t.rawBlock(List.of("_dp_yb"), yName, e -> {
            revFn.emit(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });
        // A 0x00 sign byte is appended before BIN2NUM, so the coordinate
        // decodes UNSIGNED: >= 0, but it may be up to 2^(8*coordBytes) - 1 and
        // therefore >= p. That gap is exactly what the subtraction precondition
        // turns on.
        t.setDomain(yName, Ec.Dom.NON_NEGATIVE);

        // Convert x_bytes to num
        t.toTop("_dp_xb");
        t.rawBlock(List.of("_dp_xb"), xName, e -> {
            revFn.emit(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });
        t.setDomain(xName, Ec.Dom.NON_NEGATIVE);

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

    /**
     * Affine point addition.
     *
     * <p>The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
     * denominator is zero and the correct slope is the TANGENT, (3px^2 + a)/(2py) — and
     * a = -3 on both NIST curves, so the numerator is 3px^2 - 3. The secp256k1 fix
     * (a = 0) was never ported here, so {@code p256Add(P, P)} and {@code p384Add(P, P)}
     * produced a wrong point and every contract that doubled deployed an unspendable
     * script.
     *
     * <p>Both cases are {@code s = num / den}, so only the NUMERATOR and DENOMINATOR are
     * selected and the single expensive cFieldInv still runs exactly once. rx and ry
     * below are already correct for doubling.
     *
     * <pre>
     *   cond = (px == qx)
     *   num  = cond ? 3*px^2 - 3 : (qy - py)
     *   den  = cond ? 2*py       : (qx - px)
     * </pre>
     *
     * <p>selected as {@code b + cond*(a - b)}, which needs no branch and keeps the
     * emitted op sequence identical on both paths.
     *
     * <p>NOT handled: P == -Q, whose true result is the point at infinity, which affine
     * coordinates cannot represent.
     */
    /**
     * GAP-301: coordinate canonicity, leaving {@code _canon} on the tracker.
     *
     * <p>{@code cDecomposePoint} BIN2NUMs each coordinate as an unsigned value
     * that may be &gt;= p; the curve equation reduces it mod p, so (x + p)||y
     * would pass as a point it is not the canonical encoding of. Reject it:
     * require x &lt; p AND y &lt; p (coordinates are unsigned, so the 0 &lt;=
     * bound holds by construction). The caller ANDs {@code _canon} into its
     * result so the check still returns a boolean. This mirrors secp256k1's
     * {@code emitEcOnCurve}, whose guard the a = -3 curves never received —
     * leaving {@code pNNNOnCurve} accepting inputs {@code ecOnCurve} rejects
     * even though both are documented as THE gate for untrusted points.
     */
    private static void cEmitCanonicityGuard(ECTracker t, String xName, String yName, BigInteger fieldP) {
        t.copyToTop(xName, "_x_lt");
        cPushFieldP(t, "_p_for_x", fieldP);
        t.rawBlock(List.of("_x_lt", "_p_for_x"), "_x_canon",
            e -> e.accept(new OpcodeOp("OP_LESSTHAN")));
        t.copyToTop(yName, "_y_lt");
        cPushFieldP(t, "_p_for_y", fieldP);
        t.rawBlock(List.of("_y_lt", "_p_for_y"), "_y_canon",
            e -> e.accept(new OpcodeOp("OP_LESSTHAN")));
        t.toTop("_x_canon");
        t.toTop("_y_canon");
        t.rawBlock(List.of("_x_canon", "_y_canon"), "_canon",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
    }

    private static void cAffineAdd(ECTracker t, BigInteger fieldP, BigInteger pMinus2) {
        // The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
        // denominator is zero and the correct slope is the TANGENT,
        // (3px^2 - 3) / (2py). Both cases are the same shape, `s = num / den`, so
        // only the NUMERATOR and DENOMINATOR are selected; the single expensive
        // cFieldInv still runs once.
        //
        //   cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
        //   num    = cond ? 3*px^2 - 3 : (qy - py)
        //   den    = cond ? 2*py       : (qx - px)
        //
        // selected as `b + cond*(a - b)` over the field, which needs no branch and
        // so keeps the emitted op sequence — and the tracker's static stack model —
        // identical on both paths.
        //
        // THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
        // sends it down the tangent path and returns 2P — an on-curve, entirely
        // plausible, WRONG point, which is strictly worse than the pre-fix chord
        // path: that one divided by zero (cFieldInv is Fermat, inv(0) = 0) and
        // produced an OFF-curve blob, so `assert(pNNNOnCurve(pNNNAdd(a, b)))` — the
        // idiom examples/ts/p384-primitives writes verbatim — rejected it.
        //
        // P + (-P) is the point at infinity, which affine x||y cannot represent.
        // This codegen already has a representation for O: the ALL-ZERO blob, which
        // is what `pNNNMul(P, 0n)` returns. So return that, by masking the result
        // with `notinf = NOT(px == qx AND NOT cond)`. O is not on the curve
        // (0^2 != b), so the on-curve gate rejects it and the idiom works again; and
        // it adds no failure channel to a pure value-producing expression, the same
        // reason cEmitScalarReduce reduces instead of rejecting.
        //
        // The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
        // and notinf is 0 or 1, so the product is canonical either way.
        t.copyToTop("px", "_px_eq");
        t.copyToTop("qx", "_qx_eq");
        t.rawBlock(List.of("_px_eq", "_qx_eq"), "_xeq",
                e -> e.accept(new OpcodeOp("OP_NUMEQUAL")));
        t.copyToTop("py", "_py_eq");
        t.copyToTop("qy", "_qy_eq");
        t.rawBlock(List.of("_py_eq", "_qy_eq"), "_yeq",
                e -> e.accept(new OpcodeOp("OP_NUMEQUAL")));
        t.copyToTop("_xeq", "_xeq_c");
        t.toTop("_yeq");
        t.rawBlock(List.of("_xeq_c", "_yeq"), "_cond",
                e -> e.accept(new OpcodeOp("OP_BOOLAND")));
        // notinf = NOT(xeq - cond): 1 exactly when px == qx and the points differ.
        t.toTop("_xeq");
        t.copyToTop("_cond", "_cond_c");
        t.rawBlock(List.of("_xeq", "_cond_c"), "_notinf", e -> {
            e.accept(new OpcodeOp("OP_SUB"));
            e.accept(new OpcodeOp("OP_NOT"));
        });

        // chord numerator / denominator
        t.copyToTop("qy", "_qy1");
        t.copyToTop("py", "_py1");
        cFieldSub(t, "_qy1", "_py1", "_num_chord", fieldP);
        t.copyToTop("qx", "_qx1");
        t.copyToTop("px", "_px1");
        cFieldSub(t, "_qx1", "_px1", "_den_chord", fieldP);

        // tangent numerator / denominator: 3*px^2 + a (a = -3) and 2*py
        t.copyToTop("px", "_px_t");
        cFieldSqr(t, "_px_t", "_px_sq", fieldP);
        cFieldMulConst(t, "_px_sq", 3, "_3px_sq", fieldP);
        t.pushInt("_a_neg", 3);
        cFieldSub(t, "_3px_sq", "_a_neg", "_num_tan", fieldP);
        t.copyToTop("py", "_py_t");
        cFieldMulConst(t, "_py_t", 2, "_den_tan", fieldP);

        // num = num_chord + cond*(num_tan - num_chord)
        t.copyToTop("_num_chord", "_num_chord_c");
        cFieldSub(t, "_num_tan", "_num_chord_c", "_num_diff", fieldP);
        t.copyToTop("_cond", "_cond_n");
        cFieldMul(t, "_num_diff", "_cond_n", "_num_sel", fieldP);
        cFieldAdd(t, "_num_chord", "_num_sel", "_s_num", fieldP);

        // den = den_chord + cond*(den_tan - den_chord)
        t.copyToTop("_den_chord", "_den_chord_c");
        cFieldSub(t, "_den_tan", "_den_chord_c", "_den_diff", fieldP);
        t.toTop("_cond");
        t.rename("_cond_d");
        cFieldMul(t, "_den_diff", "_cond_d", "_den_sel", fieldP);
        cFieldAdd(t, "_den_chord", "_den_sel", "_s_den", fieldP);

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

        // P == -Q -> force the all-zero point (see the header comment).
        t.toTop("rx");
        t.copyToTop("_notinf", "_notinf_x");
        t.rawBlock(List.of("rx", "_notinf_x"), "rx",
                e -> e.accept(new OpcodeOp("OP_MUL")));
        t.toTop("ry");
        t.toTop("_notinf");
        t.rawBlock(List.of("ry", "_notinf"), "ry",
                e -> e.accept(new OpcodeOp("OP_MUL")));
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
        // The inner tracker inherits the stack state AND the lattice facts: the
        // operands' proved domains are what decide which reduction shape the
        // body emits, so dropping them here would silently fall back everywhere.
        cJacobianAddAffineBody(
                new ECTracker(t.nm, e, t.options(), t.dm), false, fieldP, pMinus2);
    }

    /**
     * The mixed-add itself, emitting through an ECTracker the caller owns.
     *
     * <p>{@code keepHR} additionally leaves copies of H and R on the stack: both are zero
     * exactly when the Jacobian accumulator is the same curve point as the affine
     * operand, the one case these formulas cannot compute. See
     * cBuildJacobianAddOrDoubleInline.
     */
    private static void cJacobianAddAffineBody(ECTracker it, boolean keepHR,
                                               BigInteger fieldP, BigInteger pMinus2) {
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

        if (keepHR) {
            it.copyToTop("_H", "_H_keep");
            it.copyToTop("_R", "_R_keep");
        }

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

    /**
     * Branchless select of one Jacobian coordinate: {@code add + cond*(dbl - add)}.
     * Consumes addName, dblName and condName.
     */
    private static void cSelectCoord(ECTracker t, String addName, String dblName,
                                     String condName, String resultName, BigInteger fieldP) {
        t.copyToTop(addName, "_sel_add_c");
        cFieldSub(t, dblName, "_sel_add_c", "_sel_diff", fieldP);
        cFieldMul(t, "_sel_diff", condName, "_sel_scaled", fieldP);
        cFieldAdd(t, addName, "_sel_scaled", resultName, fieldP);
    }

    /**
     * The ladder's LAST conditional step: mixed-add, but correct when the accumulator
     * already equals the point being added.
     *
     * <p>The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the two
     * operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at infinity —
     * and since cFieldInv is Fermat (inv(0) = 0), cJacobianToAffine turns that into the
     * ALL-ZERO point instead of 2P. {@code p256Mul(P, 2n)} and {@code p384Mul(P, 2n)}
     * returned 64 / 96 zero bytes.
     *
     * <p>WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
     * c_i = k' &gt;&gt; i and k' = k + 3n, so the conditional step adds P to (c_i - 1)*P.
     * P-256 and P-384 both have cofactor 1, so P has order n and the degenerate cases are
     * exactly c_i == 2 (mod n) — accumulator == P — and c_i == 0 or 1 (mod n) —
     * accumulator == -P or O. c_i ranges over a CONTIGUOUS interval determined only by i,
     * so this is decidable by interval arithmetic rather than by sampling, and over the
     * whole domain k in [0, n-1] only two steps qualify, both at i = 0:
     *
     * <pre>
     *   k = 2  -&gt;  c_0 = 3n+2 == 2, odd, so the add runs: accumulator == P.  &lt;- bug
     *   k = 0  -&gt;  c_0 = 3n   == 0, odd, so the add runs: accumulator == -P,
     *              true result the point at infinity, which affine coordinates
     *              cannot represent; it stays the all-zero point, as before.
     * </pre>
     *
     * <p>At i &gt;= 1, c_i lies in [3n&gt;&gt;i, (4n-1)&gt;&gt;i] — the lower bound is 3n,
     * not 3n+1, because the reduce puts k = 0 in the domain.
     *
     * <p>Handling H == 0 at every step would cost ~75% more script bytes — on P-384 that
     * is another 600 KB; handling it here costs ~0.2%. The operand P is caller-supplied
     * but cannot move the exception, because the condition depends only on
     * c_i mod ord(P) and ord(P) = n for every point on these curves. Points that are NOT
     * on the curve carry no such guarantee — gate untrusted input on
     * {@code p256OnCurve} / {@code p384OnCurve} first. {@code cDecompressPubKey} now
     * enforces that itself for the one in-tree caller that takes a pubkey as input.
     *
     * <p>THE ENTIRE ARGUMENT IS CONDITIONED ON k in [0, n-1], which is only true because
     * {@code cEmitMul} reduces k mod n before adding 3n. That reduce landed one commit
     * AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS OWN IS UNSOUND: a
     * last-step-only select while the scalar is still unbounded leaves c_i free to hit
     * 0, 1 or 2 (mod n) at other steps. The two commits must land together and must never
     * be bisected, cherry-picked or reverted apart.
     *
     * <p>The interval argument does 100% of the work; there is no defence in depth here.
     * In particular c_i == 1 (mod n) — a pre-add accumulator of O — is UNREACHABLE, not
     * handled: were it reachable the select would still take the ADD path, because O is
     * carried as Z1 = 0, which makes U2 = 0 and H = -X1 != 0. Anything that changes the
     * +3n offset, the iteration count or the reduce must redo the interval check, not
     * assume this still holds.
     *
     * <p>Stack layout: [..., ax, ay, _k, jx, jy, jz] — same in and out.
     */
    private static void cBuildJacobianAddOrDoubleInline(Consumer<StackOp> e, ECTracker t,
                                                        BigInteger fieldP, BigInteger pMinus2) {
        ECTracker it = new ECTracker(t.nm, e, t.options(), t.dm);

        // Keep the pre-add accumulator: it is what must be DOUBLED in the
        // exceptional case, and the add below consumes jx/jy/jz.
        it.copyToTop("jx", "_sx");
        it.copyToTop("jy", "_sy");
        it.copyToTop("jz", "_sz");

        cJacobianAddAffineBody(it, true, fieldP, pMinus2);

        // cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
        // accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
        // signals the point at infinity.
        it.toTop("_H_keep");
        it.pushInt("_zero_h", 0);
        it.rawBlock(List.of("_H_keep", "_zero_h"), "_h_is0",
                e2 -> e2.accept(new OpcodeOp("OP_NUMEQUAL")));
        it.toTop("_R_keep");
        it.pushInt("_zero_r", 0);
        it.rawBlock(List.of("_R_keep", "_zero_r"), "_r_is0",
                e2 -> e2.accept(new OpcodeOp("OP_NUMEQUAL")));
        it.toTop("_h_is0");
        it.toTop("_r_is0");
        it.rawBlock(List.of("_h_is0", "_r_is0"), "_cond",
                e2 -> e2.accept(new OpcodeOp("OP_BOOLAND")));

        // Move the add result aside so cJacobianDouble can work on jx/jy/jz again,
        // this time holding the saved accumulator.
        it.toTop("jx"); it.rename("_add_x");
        it.toTop("jy"); it.rename("_add_y");
        it.toTop("jz"); it.rename("_add_z");
        it.toTop("_sx"); it.rename("jx");
        it.toTop("_sy"); it.rename("jy");
        it.toTop("_sz"); it.rename("jz");
        cJacobianDouble(it, fieldP, pMinus2);
        it.toTop("jx"); it.rename("_dbl_x");
        it.toTop("jy"); it.rename("_dbl_y");
        it.toTop("jz"); it.rename("_dbl_z");

        it.copyToTop("_cond", "_cond_x");
        cSelectCoord(it, "_add_x", "_dbl_x", "_cond_x", "jx", fieldP);
        it.copyToTop("_cond", "_cond_y");
        cSelectCoord(it, "_add_y", "_dbl_y", "_cond_y", "jy", fieldP);
        it.toTop("_cond"); it.rename("_cond_z");
        cSelectCoord(it, "_add_z", "_dbl_z", "_cond_z", "jz", fieldP);
    }

    // ===================================================================
    // Scalar multiplication (generic for both P-256 and P-384)
    // ===================================================================

    private static void cEmitMul(Consumer<StackOp> emit, int coordBytes,
                                  ReverseBytesFn revFn, BigInteger fieldP,
                                  BigInteger pMinus2, BigInteger curveN, BigInteger nMinus2,
                                  Ec.EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pt", "_k"), emit, opts, null);
        t.poolConstant(Ec.POOL_FIELD_P, fieldP);
        t.poolConstant(Ec.POOL_GROUP_N, curveN);
        cDecomposePoint(t, "_pt", "ax", "ay", coordBytes, revFn);

        // k' = k + 3n (three separate adds, matches Go reference)
        //
        // The "k in [1, n-1]" precondition is one the caller cannot enforce — the
        // scalar is usually an unlock argument — so reduce it first.
        t.toTop("_k");
        cEmitScalarReduce(t, "_k", "_kr", curveN);
        t.pushBigInt("_n", curveN);
        t.rawBlock(List.of("_kr", "_n"), "_kn",
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
            t.popTracked(); // _bit consumed by IF
            List<StackOp> addOps = new ArrayList<>();
            // Only the final step can be handed two equal operands — see
            // cBuildJacobianAddOrDoubleInline for why, and for what it costs not to.
            if (bit == 0) {
                cBuildJacobianAddOrDoubleInline(addOps::add, t, fieldP, pMinus2);
            } else {
                cBuildJacobianAddAffineInline(addOps::add, t, fieldP, pMinus2);
            }
            emit.accept(new IfOp(addOps, List.of()));
        }

        cJacobianToAffine(t, "_rx", "_ry", fieldP, pMinus2);

        // Clean up base point + scalar
        t.toTop("ax"); t.drop();
        t.toTop("ay"); t.drop();
        t.toTop("_k"); t.drop();

        cComposePoint(t, "_rx", "_ry", "_result", coordBytes, revFn);
        t.releaseConstant(Ec.POOL_GROUP_N);
        t.releaseConstant(Ec.POOL_FIELD_P);
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

    /**
     * Decompress a compressed pubkey: [prefix||x] → (x_num, y_num, valid).
     *
     * <p>For P-256/P-384 where a = -3:
     * <pre>
     *   y^2 = x^3 - 3x + b mod p
     *   y   = (y^2)^((p+1)/4) mod p
     * </pre>
     * then select y or p-y based on prefix parity.
     *
     * <p>{@code (y^2)^((p+1)/4)} is a square root ONLY when y^2 is a quadratic
     * residue; both primes are == 3 (mod 4), so for a non-residue it returns a square
     * root of -y^2 instead and the recovered point is NOT on the curve. Nor is x
     * checked against p: the BIN2NUM decode accepts any width-fitting value and every
     * field op silently reduces it, so a non-canonical x decompresses happily too.
     *
     * <p>Both matter because the only consumer is {@code cEmitVerifyECDSA}, which feeds
     * the result straight into {@code cEmitMul}. That ladder's exception analysis (see
     * {@code cBuildJacobianAddOrDoubleInline}) is stated for points ON the curve, where
     * cofactor 1 pins ord(P) = n; an off-curve point lands on the twist, whose order is
     * composite, so the degenerate steps the interval argument rules out become
     * reachable. The pubkey is a caller-supplied unlock argument.
     *
     * <p>So this emits a third output, {@code _dk_valid} = (x &lt; p) AND
     * (y_cand^2 == y^2) AND (prefix in {0x02, 0x03}), which the caller ANDs into the
     * verifier's boolean result. A flag, not an OP_VERIFY: {@code verifyECDSA_*} is a
     * total boolean-valued builtin and turning attacker-chosen bytes into a script
     * abort would be a liveness regression — the same argument
     * {@code cEmitScalarReduce} makes for reducing rather than rejecting.
     */
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
        t.pushTracked("_dk_prefix", Ec.Dom.UNKNOWN);
        t.pushTracked("_dk_xbytes", Ec.Dom.UNKNOWN);

        // SEC1 §2.3.4 requires the prefix to be exactly 0x02 or 0x03. The parity
        // reduction below is `BIN2NUM, 2 MOD`, which accepts far more than that:
        // 0x00 / 0x04 / 0x82 all alias to "even", and 0x83 is worse than an alias —
        // BIN2NUM(0x83) = -3 (sign-magnitude), -3 mod 2 = -1, which encodes as 0x81
        // and can never equal `_dk_y_par` in {<>, 0x01}, so the select silently
        // returns the OTHER square root. Test the byte itself.
        t.copyToTop("_dk_prefix", "_dk_pfx_in");
        t.rawBlock(List.of("_dk_pfx_in"), "_dk_pfx_ok", e -> {
            e.accept(new DupOp());
            e.accept(new PushOp(PushValue.ofHex("02")));
            e.accept(new OpcodeOp("OP_EQUAL"));
            e.accept(new SwapOp());
            e.accept(new PushOp(PushValue.ofHex("03")));
            e.accept(new OpcodeOp("OP_EQUAL"));
            e.accept(new OpcodeOp("OP_BOOLOR"));
        });

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

        // y = (y^2)^sqrtExp mod p. cFieldPow CONSUMES its base, so keep a copy of
        // y^2 for the residue check at the end. It has to sit BELOW _dk_y_cand: the
        // parity select below is an OP_IF whose branches are a bare drop / nip, so
        // nothing may come between _dk_y_cand and the negated candidate.
        t.copyToTop("_dk_y2", "_dk_y2_keep");
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
        t.popTracked(); // condition consumed by IF

        List<StackOp> thenOps = List.of(new DropOp());
        List<StackOp> elseOps = List.of(new NipOp());
        t.e.accept(new IfOp(thenOps, elseOps));

        // Remove _dk_neg_y from tracker (one of the two was consumed)
        for (int i = t.nm.size() - 1; i >= 0; i--) {
            if ("_dk_neg_y".equals(t.nm.get(i))) {
                t.removeSlotAt(i);
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

        // valid = (qy^2 == y^2) AND (qx < p) AND (prefix in {0x02, 0x03}).
        // The selected qy is y_cand or p - y_cand, so squaring it tests the same
        // residue property either way. The first conjunct rejects an x whose RHS is
        // a quadratic non-residue — the recovered point is then off the curve; the
        // second rejects a non-canonical encoding of an otherwise fine x; the third
        // rejects a prefix byte the parity reduction would otherwise alias or, for
        // 0x83, silently invert.
        t.copyToTop(qyName, "_dk_y_sq_in");
        cFieldSqr(t, "_dk_y_sq_in", "_dk_y_sq", fieldP);
        t.toTop("_dk_y_sq");
        t.toTop("_dk_y2_keep");
        t.rawBlock(List.of("_dk_y_sq", "_dk_y2_keep"), "_dk_res_ok",
            e -> e.accept(new OpcodeOp("OP_NUMEQUAL")));
        t.copyToTop(qxName, "_dk_x_lt");
        cPushFieldP(t, "_dk_p_lt", fieldP);
        t.rawBlock(List.of("_dk_x_lt", "_dk_p_lt"), "_dk_x_ok",
            e -> e.accept(new OpcodeOp("OP_LESSTHAN")));
        t.toTop("_dk_res_ok");
        t.toTop("_dk_x_ok");
        t.rawBlock(List.of("_dk_res_ok", "_dk_x_ok"), "_dk_curve_ok",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
        t.toTop("_dk_pfx_ok");
        t.rawBlock(List.of("_dk_curve_ok", "_dk_pfx_ok"), "_dk_valid",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
    }

    // ===================================================================
    // ECDSA verification (generic)
    // ===================================================================

    /**
     * Length gate for an untrusted byte argument: leaves {@code [flag, clamped]}.
     *
     * <p>{@code flag} is {@code OP_SIZE(v) == want}; {@code clamped} is {@code v}
     * forced to exactly {@code want} bytes by {@code v || 00*want}, split at
     * {@code want}, tail dropped — truncating a long value and zero-extending a
     * short one.
     *
     * <p>The clamp exists so the gate can stay a FLAG. Everything downstream peels a
     * fixed number of bytes ({@code OP_SPLIT coordBytes}, then 32/48 single-byte
     * splits inside emitReverse32/48); handed 32 &lt;= len(sig) &lt; 64 the reversal
     * runs out of bytes mid-loop and the SCRIPT ABORTS, which would make
     * {@code verifyECDSA_P256(...) || fallback} unwritable and contradict this
     * module's own totality rule (see {@code cDecompressPubKey}). Clamping first
     * makes every path total; the caller ANDs {@code flag} into the result so a
     * wrong-length argument can never verify whatever the clamped bytes computed.
     *
     * <p>Branch-free on purpose: the tracker's static stack model, and the emitted op
     * sequence, are the same for every input length — the argument {@code cAffineAdd}
     * makes for selecting operands instead of branching.
     */
    private static void cEmitLengthGate(ECTracker t, String name, int want, String flagName) {
        t.toTop(name);
        t.rawBlock(List.of(name), "", e -> {
            e.accept(new OpcodeOp("OP_SIZE"));
            e.accept(new PushOp(PushValue.of(want)));
            e.accept(new OpcodeOp("OP_NUMEQUAL"));
            e.accept(new SwapOp());
            e.accept(new PushOp(PushValue.ofHex(Ec.hexOf(new byte[want]))));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new PushOp(PushValue.of(want)));
            e.accept(new OpcodeOp("OP_SPLIT"));
            e.accept(new DropOp());
        });
        t.pushTracked(flagName, Ec.Dom.UNKNOWN);
        t.pushTracked(name, Ec.Dom.UNKNOWN);
    }

    /**
     * SEC1 §4.1.4 step 1 / FIPS 186-5 §6.4.2: verify 1 &lt;= r &lt;= n-1 and
     * 1 &lt;= s &lt;= n-1. Consumes nothing, leaves {@code _range_ok} above
     * {@code _r} and {@code _s}.
     *
     * <p>==&gt; THIS IS A UNIVERSAL FORGERY GUARD, NOT A HYGIENE CHECK. &lt;==
     *
     * <p>Nothing checked r or s at all, and {@code cGroupInv} is Fermat
     * (a^(n-2) mod n), so inv(0) = 0 instead of an error. With {@code sig = 0x00…}
     * and the contract's own genuine, PUBLIC key:
     *
     * <pre>
     *   r = s = 0            (BIN2NUM of coordBytes zero bytes -&gt; empty vector)
     *   w = s^(n-2) = 0      Fermat, no failure channel
     *   u1 = u2 = 0          every cGroupMul in the ladder is 0*0 mod n
     *   R1 = R2 = O          cEmitMul reduces 0, k' = 3n = 0 mod n, so Z3 = 0 and
     *                        cJacobianToAffine's Fermat inverse turns it all-zero
     *   R1 + R2              cAffineAdd sees xeq = yeq = 1, takes the tangent with
     *                        den = 2*0 = 0, so s = 0 and rx = ry = 0
     *   (R.x mod n) == r     OP_EQUAL(&lt;&gt;, &lt;&gt;) = 1
     * </pre>
     *
     * <p>...and {@code _dk_valid} is 1 because the pubkey is genuine. TRUE. No
     * secret, no off-curve point, not bound to the message: an all-zero signature
     * verified for ANY message under ANY public key. {@code examples/ts/p256-wallet}
     * made exactly that call its second authentication factor.
     *
     * <p>BOTH conjuncts are load-bearing and neither is redundant:
     * <ul>
     *   <li>s = 0 (or s = n, which Fermat also inverts to 0) is what collapses both
     *       ladders to O;</li>
     *   <li>r = 0 is what makes the final OP_EQUAL compare the resulting 0 against
     *       something that is also 0.</li>
     * </ul>
     * {@code r = 0, s = n} is a second spelling of the same forgery that an
     * {@code s != 0} check alone would miss, which is why the bound is {@code < n}
     * and not {@code != 0}.
     *
     * <p>A flag rather than an OP_VERIFY, for the reason
     * {@code cDecompressPubKey} gives.
     */
    private static void cEmitSigRangeGate(ECTracker t, BigInteger curveN) {
        t.copyToTop("_r", "_r_nz_in");
        t.rawBlock(List.of("_r_nz_in"), "_r_nz",
            e -> e.accept(new OpcodeOp("OP_0NOTEQUAL")));
        t.copyToTop("_r", "_r_lt_in");
        cPushGroupN(t, "_n_for_r", curveN);
        t.rawBlock(List.of("_r_lt_in", "_n_for_r"), "_r_lt",
            e -> e.accept(new OpcodeOp("OP_LESSTHAN")));
        t.rawBlock(List.of("_r_nz", "_r_lt"), "_r_ok",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));

        t.copyToTop("_s", "_s_nz_in");
        t.rawBlock(List.of("_s_nz_in"), "_s_nz",
            e -> e.accept(new OpcodeOp("OP_0NOTEQUAL")));
        t.copyToTop("_s", "_s_lt_in");
        cPushGroupN(t, "_n_for_s", curveN);
        t.rawBlock(List.of("_s_lt_in", "_n_for_s"), "_s_lt",
            e -> e.accept(new OpcodeOp("OP_LESSTHAN")));
        t.rawBlock(List.of("_s_nz", "_s_lt"), "_s_ok",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));

        t.rawBlock(List.of("_r_ok", "_s_ok"), "_range_ok",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
    }

    // ==================================================================
    // Fixed-base comb (the base is a compile-time constant)
    // ==================================================================

    /**
     * {@code k*G} by a Lim-Lee comb, for a base known at compile time.
     *
     * <p>The binary ladder runs one doubling and one conditional add per scalar BIT. A comb splits
     * the scalar into {@code w} blocks of {@code d} bits and runs one doubling and one conditional
     * add per COLUMN, so the round count falls from {@code w*d} to {@code d} at the price of a
     * {@code 2^w - 1} entry table — which costs nothing to build here, because {@code G} is a
     * constant. Measured optimum is w=3: the selection logic grows as {@code 2^w} and overtakes the
     * saving by w=5.
     *
     * <p>SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add accumulator equal to
     * the addend, its negation, or the point at infinity. {@code cBuildJacobianAddOrDoubleInline}'s
     * comment justifies using it everywhere but the last step of the BINARY ladder by an interval
     * argument over {@code c_i mod n}, and insists that argument be re-derived by anything changing
     * the offset or the iteration count. A comb changes both, so it is re-derived — as executable
     * interval arithmetic in {@code Comb.combSafeRounds}, evaluated here. Rounds it cannot prove get
     * the complete add-or-double form instead; nothing is assumed. For P-256 at w=3 it proves 81 of
     * 86 rounds.
     *
     * <p>The other half of that argument is that the accumulator never starts at infinity, which
     * needs the first digit non-zero. {@code Comb.combGeometry} searches for the scalar offset that
     * guarantees it rather than reusing the ladder's hardcoded {@code +3n} — right for P-256 at w=3
     * and WRONG for P-384.
     *
     * <p>Stack in: [_k]. Stack out: [_result].
     *
     * @return false when no geometry exists for {@code w}
     */
    private static boolean cEmitCombMulGen(Consumer<StackOp> emit, int coordBytes,
                                           ReverseBytesFn revFn, BigInteger fieldP,
                                           BigInteger pMinus2, BigInteger curveN,
                                           Comb.Curve curve, int w,
                                           Ec.EcCodegenOptions opts) {
        Comb.Params params = Comb.combGeometry(w, curve);
        if (params == null) return false;
        int d = params.d();
        List<Comb.Point> table = Comb.combTable(w, d, curve);
        boolean[] safe = Comb.combSafeRounds(params, curve);
        int entries = (1 << w) - 1;

        ECTracker t = new ECTracker(List.of("_k"), emit, opts, null);
        t.poolConstant(Ec.POOL_FIELD_P, fieldP);
        t.poolConstant(Ec.POOL_GROUP_N, curveN);

        // k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so
        // what makes the interval argument apply at all; see cEmitScalarReduce.
        t.toTop("_k");
        cEmitScalarReduce(t, "_k", "_kr", curveN);
        t.rename("_k");
        for (int i = 0; i < params.offsetMultiple(); i++) {
            String off = "_off" + i;
            t.pushConst(Ec.POOL_GROUP_N, curveN, off);
            t.rawBlock(List.of("_k", off), "_k", e -> e.accept(new OpcodeOp("OP_ADD")));
        }
        t.setDomain("_k", Ec.Dom.NON_NEGATIVE);

        // Table, resident for the whole comb: picking an entry costs 2-3 bytes
        // against a 34-byte literal push, and every round reads all of them.
        for (int j = 1; j <= entries; j++) {
            Comb.Point pt = table.get(j);
            t.pushBigInt("_Tx" + j, pt.x());
            t.pushBigInt("_Ty" + j, pt.y());
            t.setDomain("_Tx" + j, Ec.Dom.REDUCED);
            t.setDomain("_Ty" + j, Ec.Dom.REDUCED);
        }

        // Round d-1 initialises the accumulator. The first digit is non-zero by
        // construction (combGeometry), so this is a real point, never infinity.
        Ec.combEmitSelect(t, d - 1, w, d);
        t.toTop("_flag");
        t.drop();
        t.toTop("ax");
        t.rename("jx");
        t.toTop("ay");
        t.rename("jy");
        t.pushInt("jz", 1);
        t.setDomain("jz", Ec.Dom.REDUCED);

        for (int i = d - 2; i >= 0; i--) {
            cJacobianDouble(t, fieldP, pMinus2);
            Ec.combEmitSelect(t, i, w, d);

            // cJacobianAddAffineBody documents its layout as
            // [..., ax, ay, jx, jy, jz] and replaces the accumulator IN PLACE at
            // the top. The selection leaves ax/ay above jz, so restore the
            // contract before the branch — otherwise the add arm would reorder
            // the stack and the empty else arm would not, leaving the two arms
            // with different layouts at OP_ENDIF.
            t.toTop("_flag");
            t.toAlt();
            t.toTop("jx");
            t.toTop("jy");
            t.toTop("jz");
            t.fromAlt("_flag");

            t.popTracked(); // consumed by OP_IF
            List<StackOp> addOps = new ArrayList<>();
            if (safe[i]) {
                cBuildJacobianAddAffineInline(addOps::add, t, fieldP, pMinus2);
            } else {
                cBuildJacobianAddOrDoubleInline(addOps::add, t, fieldP, pMinus2);
            }
            emit.accept(new IfOp(addOps, List.of()));

            // The addend was selected fresh for this round; the add only copied it.
            t.toTop("ay");
            t.drop();
            t.toTop("ax");
            t.drop();
        }

        cJacobianToAffine(t, "_rx", "_ry", fieldP, pMinus2);

        for (int j = entries; j >= 1; j--) {
            t.toTop("_Ty" + j);
            t.drop();
            t.toTop("_Tx" + j);
            t.drop();
        }
        t.toTop("_k");
        t.drop();

        cComposePoint(t, "_rx", "_ry", "_result", coordBytes, revFn);
        t.releaseConstant(Ec.POOL_GROUP_N);
        t.releaseConstant(Ec.POOL_FIELD_P);
        return true;
    }

    /**
     * Emit the cheapest comb over the candidate window widths.
     *
     * <p>Each candidate is rendered in full and scored with the same byte-cost model the emitter is
     * measured by, and the smallest wins.
     */
    private static List<StackOp> cEmitCombBest(int coordBytes, ReverseBytesFn revFn,
                                               BigInteger fieldP, BigInteger pMinus2,
                                               BigInteger curveN, Comb.Curve curve,
                                               Ec.EcCodegenOptions opts) {
        List<StackOp> best = null;
        for (int w : new int[] {2, 3, 4}) {
            List<StackOp> ops = new ArrayList<>();
            if (!cEmitCombMulGen(ops::add, coordBytes, revFn, fieldP, pMinus2, curveN,
                    curve, w, opts)) {
                continue;
            }
            if (best == null
                    || CostModel.estimateScriptBytes(ops) < CostModel.estimateScriptBytes(best)) {
                best = ops;
            }
        }
        return best;
    }

    private static void cEmitVerifyECDSA(Consumer<StackOp> emit, int coordBytes,
                                         ReverseBytesFn revFn, BigInteger fieldP,
                                         BigInteger pMinus2, BigInteger curveN,
                                         BigInteger nMinus2, BigInteger curveB,
                                         BigInteger sqrtExp, BigInteger gx, BigInteger gy,
                                         Comb.Curve combCurve, Ec.EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_msg", "_sig", "_pk"), emit, opts, null);
        // The verifier does hundreds of reductions OUTSIDE the two ladders —
        // decompression's sqrt ladder, cGroupInv, cAffineAdd, the final
        // cGroupMod. Each ladder pools separately: cEmitMul runs on its own
        // tracker that deliberately cannot see this stack, so it cannot reach
        // this slot.
        t.poolConstant(Ec.POOL_FIELD_P, fieldP);
        t.poolConstant(Ec.POOL_GROUP_N, curveN);

        // Step 0: length gate. `_sig` and `_pk` are bare ByteString in the builtin
        // table and the type checker imposes no width, so both arrive attacker-sized.
        // Clamp them and remember whether they were the right size — see
        // cEmitLengthGate for why a clamp and not an abort. Without it `sig || junk`
        // verified identically to `sig` (fatal for any contract using signature bytes
        // as a nullifier), and a short `sig` aborted the script outright.
        cEmitLengthGate(t, "_pk", coordBytes + 1, "_pk_len_ok");
        cEmitLengthGate(t, "_sig", coordBytes * 2, "_sig_len_ok");
        t.toTop("_pk_len_ok");
        t.toTop("_sig_len_ok");
        t.rawBlock(List.of("_pk_len_ok", "_sig_len_ok"), "_len_ok",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));

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
        t.pushTracked("_r_bytes", Ec.Dom.UNKNOWN);
        t.pushTracked("_s_bytes", Ec.Dom.UNKNOWN);

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

        // Step 2b: 1 <= r, s <= n-1. Without this an all-zero signature verifies for
        // any message under any pubkey — see cEmitSigRangeGate.
        cEmitSigRangeGate(t, curveN);

        // Step 3: Decompress pubkey. Also yields `_dk_valid`: 0 when the pubkey
        // bytes do not decompress to a canonical on-curve point, which is ANDed into
        // the result below so such a key can never verify.
        cDecompressPubKey(t, "_pk", "_qx", "_qy",
            coordBytes, revFn, fieldP, pMinus2, curveB, sqrtExp);

        // Collapse the three argument verdicts into one flag. Everything below then
        // carries a single item, as it did when `_dk_valid` was the only one.
        t.toTop("_len_ok");
        t.toTop("_range_ok");
        t.rawBlock(List.of("_len_ok", "_range_ok"), "_arg_ok",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
        t.toTop("_dk_valid");
        t.rawBlock(List.of("_arg_ok", "_dk_valid"), "_input_ok",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));

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

        // u1*G. G is a compile-time constant, so this half can use a fixed-base
        // comb — one doubling and one add per COLUMN instead of per bit. u2*Q
        // below cannot: Q arrives in the witness.
        List<StackOp> combOps = null;
        if (opts != null && opts.fixedBaseComb() && combCurve != null) {
            combOps = cEmitCombBest(coordBytes, revFn, fieldP, pMinus2, curveN, combCurve, opts);
        }

        if (combOps == null) {
            t.pushBytes("_G", gPointData);
        }
        t.toTop("_u1");

        // Stash items on altstack. _input_ok goes DEEPEST — the altstack is LIFO
        // and it is popped last.
        t.toTop("_input_ok"); t.toAlt();
        t.toTop("_r_save"); t.toAlt();
        t.toTop("_u2");     t.toAlt();
        t.toTop("_qy");     t.toAlt();
        t.toTop("_qx");     t.toAlt();

        // Remove _G and _u1 from tracker before cEmitMul
        // The multiply creates its own ECTracker and cannot see items below its
        // operands. Remove them from ours.
        t.popTracked(); // _u1
        if (combOps == null) {
            t.popTracked(); // _G
        }

        if (combOps != null) {
            for (StackOp op : combOps) emit.accept(op);
        } else {
            cEmitMul(emit, coordBytes, revFn, fieldP, pMinus2, curveN, nMinus2, opts);
        }

        // After mul, one result point is on the stack
        t.pushTracked("_R1_point", Ec.Dom.UNKNOWN);

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
        t.popTracked(); // _u2
        t.popTracked(); // _Q_point
        cEmitMul(emit, coordBytes, revFn, fieldP, pMinus2, curveN, nMinus2, opts);
        t.pushTracked("_R2_point", Ec.Dom.UNKNOWN);

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

        // Restore r, then the argument verdict beneath it
        t.fromAlt("_r_save");
        t.fromAlt("_input_ok");

        // Compare
        t.toTop("_rx_mod_n");
        t.toTop("_r_save");
        t.rawBlock(List.of("_rx_mod_n", "_r_save"), "_sig_ok",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));

        // Arguments that were the wrong length, out of range, or did not decompress
        // to a canonical on-curve point can never verify, whatever the ladder made
        // of them.
        t.toTop("_input_ok");
        t.toTop("_sig_ok");
        t.rawBlock(List.of("_input_ok", "_sig_ok"), "_result",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
        t.releaseConstant(Ec.POOL_GROUP_N);
        t.releaseConstant(Ec.POOL_FIELD_P);
    }

    // ===================================================================
    // P-256 public API
    // ===================================================================

    public static void emitP256Add(Consumer<StackOp> emit) {
        emitP256Add(emit, null);
    }

    public static void emitP256Add(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pa", "_pb"), emit, opts, null);
        t.poolConstant(Ec.POOL_FIELD_P, P256_P);
        cDecomposePoint(t, "_pa", "px", "py", 32, REV32);
        cDecomposePoint(t, "_pb", "qx", "qy", 32, REV32);
        cAffineAdd(t, P256_P, P256_P_MINUS_2);
        cComposePoint(t, "rx", "ry", "_result", 32, REV32);
        t.releaseConstant(Ec.POOL_FIELD_P);
    }

    public static void emitP256Mul(Consumer<StackOp> emit) {
        emitP256Mul(emit, null);
    }

    public static void emitP256Mul(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        cEmitMul(emit, 32, REV32, P256_P, P256_P_MINUS_2, P256_N, P256_N_MINUS_2, opts);
    }

    public static void emitP256MulGen(Consumer<StackOp> emit) {
        emitP256MulGen(emit, null);
    }

    public static void emitP256MulGen(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        if (opts != null && opts.fixedBaseComb()) {
            List<StackOp> ops =
                    cEmitCombBest(32, REV32, P256_P, P256_P_MINUS_2, P256_N, Comb.P256_COMB_CURVE, opts);
            if (ops != null) {
                for (StackOp op : ops) emit.accept(op);
                return;
            }
        }
        byte[] gPoint = new byte[64];
        System.arraycopy(bigintToNBytes(P256_GX, 32), 0, gPoint, 0, 32);
        System.arraycopy(bigintToNBytes(P256_GY, 32), 0, gPoint, 32, 32);
        emit.accept(new PushOp(PushValue.ofHex(Ec.hexOf(gPoint))));
        emit.accept(new SwapOp()); // [point, scalar]
        emitP256Mul(emit, opts);
    }

    public static void emitP256Negate(Consumer<StackOp> emit) {
        emitP256Negate(emit, null);
    }

    public static void emitP256Negate(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pt"), emit, opts, null);
        t.poolConstant(Ec.POOL_FIELD_P, P256_P);
        cDecomposePoint(t, "_pt", "_nx", "_ny", 32, REV32);
        cPushFieldP(t, "_fp", P256_P);
        cFieldSub(t, "_fp", "_ny", "_neg_y", P256_P);
        cComposePoint(t, "_nx", "_neg_y", "_result", 32, REV32);
        t.releaseConstant(Ec.POOL_FIELD_P);
    }

    public static void emitP256OnCurve(Consumer<StackOp> emit) {
        emitP256OnCurve(emit, null);
    }

    public static void emitP256OnCurve(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pt"), emit, opts, null);
        t.poolConstant(Ec.POOL_FIELD_P, P256_P);
        cDecomposePoint(t, "_pt", "_x", "_y", 32, REV32);
        cEmitCanonicityGuard(t, "_x", "_y", P256_P);

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
        t.rawBlock(List.of("_y2", "_rhs"), "_curve_eq",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));

        // on-curve = canonical AND curve-equation
        t.toTop("_canon");
        t.toTop("_curve_eq");
        t.rawBlock(List.of("_canon", "_curve_eq"), "_result",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
        t.releaseConstant(Ec.POOL_FIELD_P);
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
        emitVerifyECDSA_P256(emit, null);
    }

    public static void emitVerifyECDSA_P256(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        cEmitVerifyECDSA(emit, 32, REV32,
            P256_P, P256_P_MINUS_2, P256_N, P256_N_MINUS_2,
            P256_B, P256_SQRT_EXP, P256_GX, P256_GY, Comb.P256_COMB_CURVE, opts);
    }

    // ===================================================================
    // P-384 public API
    // ===================================================================

    public static void emitP384Add(Consumer<StackOp> emit) {
        emitP384Add(emit, null);
    }

    public static void emitP384Add(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pa", "_pb"), emit, opts, null);
        t.poolConstant(Ec.POOL_FIELD_P, P384_P);
        cDecomposePoint(t, "_pa", "px", "py", 48, REV48);
        cDecomposePoint(t, "_pb", "qx", "qy", 48, REV48);
        cAffineAdd(t, P384_P, P384_P_MINUS_2);
        cComposePoint(t, "rx", "ry", "_result", 48, REV48);
        t.releaseConstant(Ec.POOL_FIELD_P);
    }

    public static void emitP384Mul(Consumer<StackOp> emit) {
        emitP384Mul(emit, null);
    }

    public static void emitP384Mul(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        cEmitMul(emit, 48, REV48, P384_P, P384_P_MINUS_2, P384_N, P384_N_MINUS_2, opts);
    }

    public static void emitP384MulGen(Consumer<StackOp> emit) {
        emitP384MulGen(emit, null);
    }

    public static void emitP384MulGen(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        if (opts != null && opts.fixedBaseComb()) {
            List<StackOp> ops =
                    cEmitCombBest(48, REV48, P384_P, P384_P_MINUS_2, P384_N, Comb.P384_COMB_CURVE, opts);
            if (ops != null) {
                for (StackOp op : ops) emit.accept(op);
                return;
            }
        }
        byte[] gPoint = new byte[96];
        System.arraycopy(bigintToNBytes(P384_GX, 48), 0, gPoint, 0, 48);
        System.arraycopy(bigintToNBytes(P384_GY, 48), 0, gPoint, 48, 48);
        emit.accept(new PushOp(PushValue.ofHex(Ec.hexOf(gPoint))));
        emit.accept(new SwapOp()); // [point, scalar]
        emitP384Mul(emit, opts);
    }

    public static void emitP384Negate(Consumer<StackOp> emit) {
        emitP384Negate(emit, null);
    }

    public static void emitP384Negate(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pt"), emit, opts, null);
        t.poolConstant(Ec.POOL_FIELD_P, P384_P);
        cDecomposePoint(t, "_pt", "_nx", "_ny", 48, REV48);
        cPushFieldP(t, "_fp", P384_P);
        cFieldSub(t, "_fp", "_ny", "_neg_y", P384_P);
        cComposePoint(t, "_nx", "_neg_y", "_result", 48, REV48);
        t.releaseConstant(Ec.POOL_FIELD_P);
    }

    public static void emitP384OnCurve(Consumer<StackOp> emit) {
        emitP384OnCurve(emit, null);
    }

    public static void emitP384OnCurve(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pt"), emit, opts, null);
        t.poolConstant(Ec.POOL_FIELD_P, P384_P);
        cDecomposePoint(t, "_pt", "_x", "_y", 48, REV48);
        cEmitCanonicityGuard(t, "_x", "_y", P384_P);

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
        t.rawBlock(List.of("_y2", "_rhs"), "_curve_eq",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));

        // on-curve = canonical AND curve-equation
        t.toTop("_canon");
        t.toTop("_curve_eq");
        t.rawBlock(List.of("_canon", "_curve_eq"), "_result",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
        t.releaseConstant(Ec.POOL_FIELD_P);
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
        emitVerifyECDSA_P384(emit, null);
    }

    public static void emitVerifyECDSA_P384(Consumer<StackOp> emit, Ec.EcCodegenOptions opts) {
        cEmitVerifyECDSA(emit, 48, REV48,
            P384_P, P384_P_MINUS_2, P384_N, P384_N_MINUS_2,
            P384_B, P384_SQRT_EXP, P384_GX, P384_GY, Comb.P384_COMB_CURVE, opts);
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
        dispatch(funcName, emit, null);
    }

    public static void dispatch(String funcName, Consumer<StackOp> emit,
                                Ec.EcCodegenOptions opts) {
        switch (funcName) {
            case "p256Add" -> emitP256Add(emit, opts);
            case "p256Mul" -> emitP256Mul(emit, opts);
            case "p256MulGen" -> emitP256MulGen(emit, opts);
            case "p256Negate" -> emitP256Negate(emit, opts);
            case "p256OnCurve" -> emitP256OnCurve(emit, opts);
            // Pure byte shuffling with no field arithmetic: the flags cannot
            // reach it, so it deliberately takes no options.
            case "p256EncodeCompressed" -> emitP256EncodeCompressed(emit);
            case "p384Add" -> emitP384Add(emit, opts);
            case "p384Mul" -> emitP384Mul(emit, opts);
            case "p384MulGen" -> emitP384MulGen(emit, opts);
            case "p384Negate" -> emitP384Negate(emit, opts);
            case "p384OnCurve" -> emitP384OnCurve(emit, opts);
            case "p384EncodeCompressed" -> emitP384EncodeCompressed(emit);
            case "verifyECDSA_P256" -> emitVerifyECDSA_P256(emit, opts);
            case "verifyECDSA_P384" -> emitVerifyECDSA_P384(emit, opts);
            default -> throw new RuntimeException("unknown NIST EC builtin: " + funcName);
        }
    }
}
