package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.NipOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PickOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.RollOp;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.SwapOp;

/**
 * secp256k1 EC codegen for Bitcoin Script.
 *
 * <p>Direct port of {@code compilers/python/runar_compiler/codegen/ec.py}.
 * Exposes emitters for the full secp256k1 builtin surface: {@code ecAdd},
 * {@code ecMul}, {@code ecMulGen}, {@code ecNegate}, {@code ecOnCurve},
 * {@code ecModReduce}, {@code ecEncodeCompressed}, {@code ecMakePoint},
 * {@code ecPointX}, {@code ecPointY}.
 *
 * <p>Point representation is 64 bytes (x[32] || y[32], big-endian unsigned,
 * no prefix byte). Internal scalar multiplication uses Jacobian coordinates.
 *
 * <p>Every helper here preserves the {@code ECTracker} name-slot contract
 * from the Python reference so the emitted {@link StackOp} stream is
 * byte-for-byte identical.
 */
public final class Ec {

    private Ec() {}

    // ------------------------------------------------------------------
    // Curve constants
    // ------------------------------------------------------------------

    /** secp256k1 field prime p = 2^256 - 2^32 - 977. */
    public static final BigInteger EC_FIELD_P = new BigInteger(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);

    /** p - 2, used for Fermat's little theorem modular inverse. */
    public static final BigInteger EC_FIELD_P_MINUS_2 =
        EC_FIELD_P.subtract(BigInteger.TWO);

    /** secp256k1 generator x-coordinate. */
    public static final BigInteger EC_GEN_X = new BigInteger(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);

    /** secp256k1 generator y-coordinate. */
    public static final BigInteger EC_GEN_Y = new BigInteger(
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);

    /** secp256k1 group order n. */
    public static final BigInteger EC_CURVE_N = new BigInteger(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);

    private static byte[] bigintToBytes32(BigInteger n) {
        byte[] src = n.toByteArray();
        byte[] out = new byte[32];
        int copyLen = Math.min(src.length, 32);
        int srcOff = src.length > 32 ? src.length - 32 : 0;
        int dstOff = 32 - copyLen;
        System.arraycopy(src, srcOff, out, dstOff, copyLen);
        return out;
    }

    private static String hexOf(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    // ==================================================================
    // ECTracker: named stack slot tracker (mirrors Python ECTracker)
    // ==================================================================

    static final class ECTracker {
        final List<String> nm;
        final Consumer<StackOp> e;

        ECTracker(List<String> init, Consumer<StackOp> emit) {
            this.nm = new ArrayList<>(init);
            this.e = emit;
        }

        int findDepth(String name) {
            for (int i = nm.size() - 1; i >= 0; i--) {
                if (name.equals(nm.get(i))) return nm.size() - 1 - i;
            }
            throw new RuntimeException("ECTracker: '" + name + "' not on stack " + nm);
        }

        void pushBytes(String n, byte[] v) {
            e.accept(new PushOp(PushValue.ofHex(hexOf(v))));
            nm.add(n);
        }

        void pushBigInt(String n, BigInteger v) {
            e.accept(new PushOp(PushValue.of(v)));
            nm.add(n);
        }

        void pushInt(String n, long v) {
            e.accept(new PushOp(PushValue.of(v)));
            nm.add(n);
        }

        void dup(String n) {
            e.accept(new DupOp());
            nm.add(n);
        }

        void drop() {
            e.accept(new DropOp());
            if (!nm.isEmpty()) nm.remove(nm.size() - 1);
        }

        void nip() {
            e.accept(new NipOp());
            int L = nm.size();
            if (L >= 2) {
                String top = nm.get(L - 1);
                nm.remove(L - 1);
                nm.remove(L - 2);
                nm.add(top);
            }
        }

        void over(String n) {
            e.accept(new OverOp());
            nm.add(n);
        }

        void swap() {
            e.accept(new SwapOp());
            int L = nm.size();
            if (L >= 2) {
                String t = nm.get(L - 1);
                nm.set(L - 1, nm.get(L - 2));
                nm.set(L - 2, t);
            }
        }

        void rot() {
            e.accept(new RotOp());
            int L = nm.size();
            if (L >= 3) {
                String r = nm.get(L - 3);
                nm.remove(L - 3);
                nm.add(r);
            }
        }

        void op(String code) {
            e.accept(new OpcodeOp(code));
        }

        void roll(int d) {
            if (d == 0) return;
            if (d == 1) { swap(); return; }
            if (d == 2) { rot(); return; }
            e.accept(new PushOp(PushValue.of(d)));
            nm.add("");
            e.accept(new RollOp(d));
            nm.remove(nm.size() - 1); // pop push placeholder
            int idx = nm.size() - 1 - d;
            String r = nm.get(idx);
            nm.remove(idx);
            nm.add(r);
        }

        void pick(int d, String n) {
            if (d == 0) { dup(n); return; }
            if (d == 1) { over(n); return; }
            e.accept(new PushOp(PushValue.of(d)));
            nm.add("");
            e.accept(new PickOp(d));
            nm.remove(nm.size() - 1);
            nm.add(n);
        }

        void toTop(String name) {
            roll(findDepth(name));
        }

        void copyToTop(String name, String n) {
            pick(findDepth(name), n);
        }

        void toAlt() {
            op("OP_TOALTSTACK");
            if (!nm.isEmpty()) nm.remove(nm.size() - 1);
        }

        void fromAlt(String n) {
            op("OP_FROMALTSTACK");
            nm.add(n);
        }

        void rename(String n) {
            if (!nm.isEmpty()) nm.set(nm.size() - 1, n);
        }

        /**
         * Emit raw opcodes; tracker only records net stack effect. *produce*
         * = "" means no output pushed.
         */
        void rawBlock(List<String> consume, String produce, Consumer<Consumer<StackOp>> fn) {
            for (int i = 0; i < consume.size(); i++) {
                if (!nm.isEmpty()) nm.remove(nm.size() - 1);
            }
            fn.accept(this.e);
            if (produce != null && !produce.isEmpty()) {
                nm.add(produce);
            }
        }

        /** Emit if/else with tracked stack effect. resultName="" => no result. */
        void emitIf(String condName,
                    Consumer<Consumer<StackOp>> thenFn,
                    Consumer<Consumer<StackOp>> elseFn,
                    String resultName) {
            toTop(condName);
            // condition consumed
            if (!nm.isEmpty()) nm.remove(nm.size() - 1);
            List<StackOp> thenOps = new ArrayList<>();
            List<StackOp> elseOps = new ArrayList<>();
            thenFn.accept(thenOps::add);
            elseFn.accept(elseOps::add);
            this.e.accept(new IfOp(thenOps, elseOps));
            if (resultName != null && !resultName.isEmpty()) {
                nm.add(resultName);
            }
        }
    }

    // ==================================================================
    // Field arithmetic helpers (mod p)
    // ==================================================================

    private static void pushFieldP(ECTracker t, String name) {
        t.pushBigInt(name, EC_FIELD_P);
    }

    private static void fieldMod(ECTracker t, String aName, String resultName) {
        t.toTop(aName);
        pushFieldP(t, "_fmod_p");
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

    private static void fieldAdd(ECTracker t, String aName, String bName, String resultName) {
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fadd_sum", e -> e.accept(new OpcodeOp("OP_ADD")));
        fieldMod(t, "_fadd_sum", resultName);
    }

    private static void fieldSub(ECTracker t, String aName, String bName, String resultName) {
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fsub_diff", e -> e.accept(new OpcodeOp("OP_SUB")));
        fieldMod(t, "_fsub_diff", resultName);
    }

    private static void fieldMul(ECTracker t, String aName, String bName, String resultName) {
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fmul_prod", e -> e.accept(new OpcodeOp("OP_MUL")));
        fieldMod(t, "_fmul_prod", resultName);
    }

    private static void fieldMulConst(ECTracker t, String aName, long c, String resultName) {
        t.toTop(aName);
        t.rawBlock(List.of(aName), "_fmc_prod", e -> {
            if (c == 2L) {
                e.accept(new OpcodeOp("OP_2MUL"));
            } else {
                e.accept(new PushOp(PushValue.of(c)));
                e.accept(new OpcodeOp("OP_MUL"));
            }
        });
        fieldMod(t, "_fmc_prod", resultName);
    }

    private static void fieldSqr(ECTracker t, String aName, String resultName) {
        t.copyToTop(aName, "_fsqr_copy");
        fieldMul(t, aName, "_fsqr_copy", resultName);
    }

    /** Compute a^(p-2) mod p via square-and-multiply. Consumes {@code aName}. */
    private static void fieldInv(ECTracker t, String aName, String resultName) {
        // p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
        // Bits 255..32: 222 bits of 1 + bit 32 which is 0 (handled below).

        // Start: result = a (bit 255 = 1)
        t.copyToTop(aName, "_inv_r");
        // Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0.
        for (int i = 0; i < 222; i++) {
            fieldSqr(t, "_inv_r", "_inv_r2");
            t.rename("_inv_r");
            t.copyToTop(aName, "_inv_a");
            fieldMul(t, "_inv_r", "_inv_a", "_inv_m");
            t.rename("_inv_r");
        }
        // Bit 32 is 0: square only (no multiply)
        fieldSqr(t, "_inv_r", "_inv_r2");
        t.rename("_inv_r");
        // Bits 31..0 of p-2
        long lowBits = EC_FIELD_P_MINUS_2.and(BigInteger.valueOf(0xffffffffL)).longValueExact();
        for (int i = 31; i >= 0; i--) {
            fieldSqr(t, "_inv_r", "_inv_r2");
            t.rename("_inv_r");
            if (((lowBits >> i) & 1L) == 1L) {
                t.copyToTop(aName, "_inv_a");
                fieldMul(t, "_inv_r", "_inv_a", "_inv_m");
                t.rename("_inv_r");
            }
        }
        // Clean up original input and rename result
        t.toTop(aName);
        t.drop();
        t.toTop("_inv_r");
        t.rename(resultName);
    }

    // ==================================================================
    // Point decompose / compose
    // ==================================================================

    private static void emitReverse32(Consumer<StackOp> e) {
        e.accept(new OpcodeOp("OP_0"));
        e.accept(new SwapOp());
        for (int i = 0; i < 32; i++) {
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

    private static void decomposePoint(ECTracker t, String pointName, String xName, String yName) {
        t.toTop(pointName);
        t.rawBlock(List.of(pointName), "", e -> {
            e.accept(new PushOp(PushValue.of(32)));
            e.accept(new OpcodeOp("OP_SPLIT"));
        });
        // Manually track the two new items
        t.nm.add("_dp_xb");
        t.nm.add("_dp_yb");

        // Convert y_bytes (on top) to num
        t.rawBlock(List.of("_dp_yb"), yName, e -> {
            emitReverse32(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });

        // Convert x_bytes to num
        t.toTop("_dp_xb");
        t.rawBlock(List.of("_dp_xb"), xName, e -> {
            emitReverse32(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });

        // Stack: [yName, xName] -> swap to [xName, yName]
        t.swap();
    }

    private static void composePoint(ECTracker t, String xName, String yName, String resultName) {
        t.toTop(xName);
        t.rawBlock(List.of(xName), "_cp_xb", e -> {
            e.accept(new PushOp(PushValue.of(33)));
            e.accept(new OpcodeOp("OP_NUM2BIN"));
            e.accept(new PushOp(PushValue.of(32)));
            e.accept(new OpcodeOp("OP_SPLIT"));
            e.accept(new DropOp());
            emitReverse32(e);
        });

        t.toTop(yName);
        t.rawBlock(List.of(yName), "_cp_yb", e -> {
            e.accept(new PushOp(PushValue.of(33)));
            e.accept(new OpcodeOp("OP_NUM2BIN"));
            e.accept(new PushOp(PushValue.of(32)));
            e.accept(new OpcodeOp("OP_SPLIT"));
            e.accept(new DropOp());
            emitReverse32(e);
        });

        t.toTop("_cp_xb");
        t.toTop("_cp_yb");
        t.rawBlock(List.of("_cp_xb", "_cp_yb"), resultName,
            e -> e.accept(new OpcodeOp("OP_CAT")));
    }

    // ==================================================================
    // Affine point addition (for ecAdd)
    // ==================================================================

    private static void affineAdd(ECTracker t) {
        // s_num = qy - py
        t.copyToTop("qy", "_qy1");
        t.copyToTop("py", "_py1");
        fieldSub(t, "_qy1", "_py1", "_s_num");

        // s_den = qx - px
        t.copyToTop("qx", "_qx1");
        t.copyToTop("px", "_px1");
        fieldSub(t, "_qx1", "_px1", "_s_den");

        // s = s_num / s_den mod p
        fieldInv(t, "_s_den", "_s_den_inv");
        fieldMul(t, "_s_num", "_s_den_inv", "_s");

        // rx = s^2 - px - qx mod p
        t.copyToTop("_s", "_s_keep");
        fieldSqr(t, "_s", "_s2");
        t.copyToTop("px", "_px2");
        fieldSub(t, "_s2", "_px2", "_rx1");
        t.copyToTop("qx", "_qx2");
        fieldSub(t, "_rx1", "_qx2", "rx");

        // ry = s * (px - rx) - py mod p
        t.copyToTop("px", "_px3");
        t.copyToTop("rx", "_rx2");
        fieldSub(t, "_px3", "_rx2", "_px_rx");
        fieldMul(t, "_s_keep", "_px_rx", "_s_px_rx");
        t.copyToTop("py", "_py2");
        fieldSub(t, "_s_px_rx", "_py2", "ry");

        // Clean up original points
        t.toTop("px"); t.drop();
        t.toTop("py"); t.drop();
        t.toTop("qx"); t.drop();
        t.toTop("qy"); t.drop();
    }

    // ==================================================================
    // Jacobian point operations (for ecMul)
    // ==================================================================

    private static void jacobianDouble(ECTracker t) {
        // Save copies for later use
        t.copyToTop("jy", "_jy_save");
        t.copyToTop("jx", "_jx_save");
        t.copyToTop("jz", "_jz_save");

        // A = jy^2
        fieldSqr(t, "jy", "_A");

        // B = 4 * jx * A
        t.copyToTop("_A", "_A_save");
        fieldMul(t, "jx", "_A", "_xA");
        t.pushInt("_four", 4);
        fieldMul(t, "_xA", "_four", "_B");

        // C = 8 * A^2
        fieldSqr(t, "_A_save", "_A2");
        t.pushInt("_eight", 8);
        fieldMul(t, "_A2", "_eight", "_C");

        // D = 3 * X^2
        fieldSqr(t, "_jx_save", "_x2");
        t.pushInt("_three", 3);
        fieldMul(t, "_x2", "_three", "_D");

        // nx = D^2 - 2*B
        t.copyToTop("_D", "_D_save");
        t.copyToTop("_B", "_B_save");
        fieldSqr(t, "_D", "_D2");
        t.copyToTop("_B", "_B1");
        fieldMulConst(t, "_B1", 2, "_2B");
        fieldSub(t, "_D2", "_2B", "_nx");

        // ny = D*(B - nx) - C
        t.copyToTop("_nx", "_nx_copy");
        fieldSub(t, "_B_save", "_nx_copy", "_B_nx");
        fieldMul(t, "_D_save", "_B_nx", "_D_B_nx");
        fieldSub(t, "_D_B_nx", "_C", "_ny");

        // nz = 2 * Y * Z
        fieldMul(t, "_jy_save", "_jz_save", "_yz");
        fieldMulConst(t, "_yz", 2, "_nz");

        // Clean up leftovers: _B and old jz (only copied, never consumed)
        t.toTop("_B"); t.drop();
        t.toTop("jz"); t.drop();
        t.toTop("_nx"); t.rename("jx");
        t.toTop("_ny"); t.rename("jy");
        t.toTop("_nz"); t.rename("jz");
    }

    private static void jacobianToAffine(ECTracker t, String rxName, String ryName) {
        fieldInv(t, "jz", "_zinv");
        t.copyToTop("_zinv", "_zinv_keep");
        fieldSqr(t, "_zinv", "_zinv2");
        t.copyToTop("_zinv2", "_zinv2_keep");
        fieldMul(t, "_zinv_keep", "_zinv2", "_zinv3");
        fieldMul(t, "jx", "_zinv2_keep", rxName);
        fieldMul(t, "jy", "_zinv3", ryName);
    }

    // ==================================================================
    // Jacobian mixed addition (P_jacobian + Q_affine)
    // ==================================================================

    /**
     * Build Jacobian mixed-add ops for use inside OP_IF. Uses an inner
     * ECTracker to leverage field arithmetic helpers.
     *
     * Stack: [..., ax, ay, _k, jx, jy, jz]
     */
    private static void buildJacobianAddAffineInline(Consumer<StackOp> e, ECTracker t) {
        ECTracker it = new ECTracker(t.nm, e);

        // Save copies of values consumed but needed later
        it.copyToTop("jz", "_jz_for_z1cu");
        it.copyToTop("jz", "_jz_for_z3");
        it.copyToTop("jy", "_jy_for_y3");
        it.copyToTop("jx", "_jx_for_u1h2");

        // Z1sq = jz^2
        fieldSqr(it, "jz", "_Z1sq");

        // Z1cu = _jz_for_z1cu * Z1sq
        it.copyToTop("_Z1sq", "_Z1sq_for_u2");
        fieldMul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu");

        // U2 = ax * Z1sq_for_u2
        it.copyToTop("ax", "_ax_c");
        fieldMul(it, "_ax_c", "_Z1sq_for_u2", "_U2");

        // S2 = ay * Z1cu
        it.copyToTop("ay", "_ay_c");
        fieldMul(it, "_ay_c", "_Z1cu", "_S2");

        // H = U2 - jx
        fieldSub(it, "_U2", "jx", "_H");

        // R = S2 - jy
        fieldSub(it, "_S2", "jy", "_R");

        // Save copies of H
        it.copyToTop("_H", "_H_for_h3");
        it.copyToTop("_H", "_H_for_z3");

        // H2 = H^2
        fieldSqr(it, "_H", "_H2");

        // Save H2 for U1H2
        it.copyToTop("_H2", "_H2_for_u1h2");

        // H3 = H_for_h3 * H2
        fieldMul(it, "_H_for_h3", "_H2", "_H3");

        // U1H2 = _jx_for_u1h2 * H2_for_u1h2
        fieldMul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2");

        // Save R, U1H2, H3 for Y3
        it.copyToTop("_R", "_R_for_y3");
        it.copyToTop("_U1H2", "_U1H2_for_y3");
        it.copyToTop("_H3", "_H3_for_y3");

        // X3 = R^2 - H3 - 2*U1H2
        fieldSqr(it, "_R", "_R2");
        fieldSub(it, "_R2", "_H3", "_x3_tmp");
        fieldMulConst(it, "_U1H2", 2, "_2U1H2");
        fieldSub(it, "_x3_tmp", "_2U1H2", "_X3");

        // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
        it.copyToTop("_X3", "_X3_c");
        fieldSub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x");
        fieldMul(it, "_R_for_y3", "_u_minus_x", "_r_tmp");
        fieldMul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3");
        fieldSub(it, "_r_tmp", "_jy_h3", "_Y3");

        // Z3 = _jz_for_z3 * _H_for_z3
        fieldMul(it, "_jz_for_z3", "_H_for_z3", "_Z3");

        // Rename results to jx/jy/jz
        it.toTop("_X3"); it.rename("jx");
        it.toTop("_Y3"); it.rename("jy");
        it.toTop("_Z3"); it.rename("jz");
    }

    // ==================================================================
    // Public entry points
    // ==================================================================

    public static void emitEcAdd(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pa", "_pb"), emit);
        decomposePoint(t, "_pa", "px", "py");
        decomposePoint(t, "_pb", "qx", "qy");
        affineAdd(t);
        composePoint(t, "rx", "ry", "_result");
    }

    public static void emitEcMul(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pt", "_k"), emit);
        decomposePoint(t, "_pt", "ax", "ay");

        // k' = k + 3n
        t.toTop("_k");
        t.pushBigInt("_n", EC_CURVE_N);
        t.rawBlock(List.of("_k", "_n"), "_kn", e -> e.accept(new OpcodeOp("OP_ADD")));
        t.pushBigInt("_n2", EC_CURVE_N);
        t.rawBlock(List.of("_kn", "_n2"), "_kn2", e -> e.accept(new OpcodeOp("OP_ADD")));
        t.pushBigInt("_n3", EC_CURVE_N);
        t.rawBlock(List.of("_kn2", "_n3"), "_kn3", e -> e.accept(new OpcodeOp("OP_ADD")));
        t.rename("_k");

        // Init accumulator = P
        t.copyToTop("ax", "jx");
        t.copyToTop("ay", "jy");
        t.pushInt("jz", 1);

        // 257 iterations: bits 256 down to 0
        for (int bit = 256; bit >= 0; bit--) {
            // Double accumulator
            jacobianDouble(t);

            // Extract bit
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

            // Move _bit to TOS and remove from tracker BEFORE generating add ops
            t.toTop("_bit");
            t.nm.remove(t.nm.size() - 1); // _bit consumed by IF
            List<StackOp> addOps = new ArrayList<>();
            buildJacobianAddAffineInline(addOps::add, t);
            emit.accept(new IfOp(addOps, List.of()));
        }

        // Convert Jacobian to affine
        jacobianToAffine(t, "_rx", "_ry");

        // Clean up base point and scalar
        t.toTop("ax"); t.drop();
        t.toTop("ay"); t.drop();
        t.toTop("_k"); t.drop();

        // Compose result
        composePoint(t, "_rx", "_ry", "_result");
    }

    public static void emitEcMulGen(Consumer<StackOp> emit) {
        byte[] gPoint = new byte[64];
        byte[] gx = bigintToBytes32(EC_GEN_X);
        byte[] gy = bigintToBytes32(EC_GEN_Y);
        System.arraycopy(gx, 0, gPoint, 0, 32);
        System.arraycopy(gy, 0, gPoint, 32, 32);
        emit.accept(new PushOp(PushValue.ofHex(hexOf(gPoint))));
        emit.accept(new SwapOp());
        emitEcMul(emit);
    }

    public static void emitEcNegate(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pt"), emit);
        decomposePoint(t, "_pt", "_nx", "_ny");
        pushFieldP(t, "_fp");
        fieldSub(t, "_fp", "_ny", "_neg_y");
        composePoint(t, "_nx", "_neg_y", "_result");
    }

    public static void emitEcOnCurve(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pt"), emit);
        decomposePoint(t, "_pt", "_x", "_y");

        // lhs = y^2
        fieldSqr(t, "_y", "_y2");

        // rhs = x^3 + 7
        t.copyToTop("_x", "_x_copy");
        fieldSqr(t, "_x", "_x2");
        fieldMul(t, "_x2", "_x_copy", "_x3");
        t.pushInt("_seven", 7);
        fieldAdd(t, "_x3", "_seven", "_rhs");

        // Compare
        t.toTop("_y2");
        t.toTop("_rhs");
        t.rawBlock(List.of("_y2", "_rhs"), "_result",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));
    }

    public static void emitEcModReduce(Consumer<StackOp> emit) {
        emit.accept(new OpcodeOp("OP_2DUP"));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new RotOp());
        emit.accept(new DropOp());
        emit.accept(new OverOp());
        emit.accept(new OpcodeOp("OP_ADD"));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_MOD"));
    }

    public static void emitEcEncodeCompressed(Consumer<StackOp> emit) {
        // Split at 32: [x_bytes, y_bytes]
        emit.accept(new PushOp(PushValue.of(32)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        // Get last byte of y for parity
        emit.accept(new OpcodeOp("OP_SIZE"));
        emit.accept(new PushOp(PushValue.of(1)));
        emit.accept(new OpcodeOp("OP_SUB"));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        // Stack: [x_bytes, y_prefix, last_byte]
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
        emit.accept(new PushOp(PushValue.of(2)));
        emit.accept(new OpcodeOp("OP_MOD"));
        // Stack: [x_bytes, y_prefix, parity]
        emit.accept(new SwapOp());
        emit.accept(new DropOp());
        // Stack: [x_bytes, parity]
        emit.accept(new IfOp(
            List.of(new PushOp(PushValue.ofHex("03"))),
            List.of(new PushOp(PushValue.ofHex("02")))
        ));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_CAT"));
    }

    public static void emitEcMakePoint(Consumer<StackOp> emit) {
        // y to 32-byte BE
        emit.accept(new PushOp(PushValue.of(33)));
        emit.accept(new OpcodeOp("OP_NUM2BIN"));
        emit.accept(new PushOp(PushValue.of(32)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new DropOp());
        emitReverse32(emit);
        // Stack: [x_num, y_be]
        emit.accept(new SwapOp());
        // x to 32-byte BE
        emit.accept(new PushOp(PushValue.of(33)));
        emit.accept(new OpcodeOp("OP_NUM2BIN"));
        emit.accept(new PushOp(PushValue.of(32)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new DropOp());
        emitReverse32(emit);
        // Stack: [y_be, x_be]
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_CAT"));
    }

    public static void emitEcPointX(Consumer<StackOp> emit) {
        emit.accept(new PushOp(PushValue.of(32)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new DropOp());
        emitReverse32(emit);
        emit.accept(new PushOp(PushValue.ofHex("00")));
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
    }

    public static void emitEcPointY(Consumer<StackOp> emit) {
        emit.accept(new PushOp(PushValue.of(32)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new SwapOp());
        emit.accept(new DropOp());
        emitReverse32(emit);
        emit.accept(new PushOp(PushValue.ofHex("00")));
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
    }

    // ==================================================================
    // Dispatch
    // ==================================================================

    private static final java.util.Set<String> NAMES = java.util.Set.of(
        "ecAdd", "ecMul", "ecMulGen",
        "ecNegate", "ecOnCurve", "ecModReduce",
        "ecEncodeCompressed", "ecMakePoint",
        "ecPointX", "ecPointY"
    );

    public static boolean isEcBuiltin(String name) {
        return NAMES.contains(name);
    }

    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        switch (funcName) {
            case "ecAdd" -> emitEcAdd(emit);
            case "ecMul" -> emitEcMul(emit);
            case "ecMulGen" -> emitEcMulGen(emit);
            case "ecNegate" -> emitEcNegate(emit);
            case "ecOnCurve" -> emitEcOnCurve(emit);
            case "ecModReduce" -> emitEcModReduce(emit);
            case "ecEncodeCompressed" -> emitEcEncodeCompressed(emit);
            case "ecMakePoint" -> emitEcMakePoint(emit);
            case "ecPointX" -> emitEcPointX(emit);
            case "ecPointY" -> emitEcPointY(emit);
            default -> throw new RuntimeException("unknown EC builtin: " + funcName);
        }
    }
}
