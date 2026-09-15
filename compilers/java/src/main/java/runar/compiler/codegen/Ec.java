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

    static String hexOf(byte[] b) {
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

    static void emitReverse32(Consumer<StackOp> e) {
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

    /**
     * CL-BUG-095 — length gate for a {@code Point} argument, ABORTING form.
     *
     * <p>A {@code Point} is DEFINED as exactly {@code want} bytes (x ‖ y, big-endian,
     * no prefix). Nothing checked that: {@code Point} carries no width in the builtin
     * table, and every one of these values arrives as an unlock argument, so the blob
     * is attacker-sized. Surplus bytes were then silently DISCARDED, because
     * {@code decomposePoint} splits at the coordinate width and {@code emitReverse32}
     * reverses exactly 32 bytes and drops whatever is left over — so
     * {@code ecOnCurve(G ‖ 0xff)} returned TRUE and {@code ecEncodeCompressed} took its
     * parity bit from the surplus.
     *
     * <p>This is NOT a new failure channel. An UNDER-length point already aborted, by
     * accident: {@code OP_SPLIT} runs off the end of the value. The gate makes the same
     * outcome explicit, and extends it to the over-length case that used to pass.
     *
     * <p>Aborting is right for every Point consumer that produces a VALUE and has no
     * error channel to report through — {@code ecAdd}, {@code ecMul}, {@code ecNegate},
     * {@code ecPointX}, {@code ecPointY}, {@code ecEncodeCompressed}. There is no correct
     * value to return for a blob that is not a point. The PREDICATES ({@code ecOnCurve}
     * and friends) use {@link #emitPointLengthGate} instead, because for them "no" is an
     * answer.
     */
    public static void emitPointLenVerify(Consumer<StackOp> e, int want) {
        e.accept(new OpcodeOp("OP_SIZE"));
        e.accept(new PushOp(PushValue.of(want)));
        e.accept(new OpcodeOp("OP_NUMEQUALVERIFY"));
    }

    /**
     * CL-BUG-095 — length gate for a {@code Point} argument, CLAMPING form: leaves
     * {@code [flag, clamped]}, where {@code clamped} is the value forced to exactly
     * {@code want} bytes ({@code v ‖ 00*want} split at {@code want}, tail dropped) and
     * {@code flag} is {@code OP_SIZE(v) == want}.
     *
     * <p>Same shape, and the same reasoning, as {@code cEmitLengthGate} in
     * P256P384.java: the clamp exists so the gate can stay a FLAG. It is used by the
     * on-curve predicates, whose whole job is to answer "is this an acceptable point?"
     * over untrusted bytes — and for a wrong-length blob the correct answer is
     * {@code false}, not an aborted script. Aborting would break
     * {@code if (ecOnCurve(p)) { … } else { … }}, which is the exact idiom this module's
     * own comments tell contract authors to write. The caller ANDs {@code flag} into its
     * boolean result, so whatever the clamped bytes happen to compute can never make a
     * wrong-length point certify as on-curve.
     *
     * <p>Branch-free: the emitted op sequence, and the tracker's static stack model, are
     * identical for every input length.
     */
    public static void emitPointLengthGate(ECTracker t, String name, int want, String flagName) {
        t.toTop(name);
        t.rawBlock(List.of(name), "", e -> {
            e.accept(new OpcodeOp("OP_SIZE"));
            e.accept(new PushOp(PushValue.of(want)));
            e.accept(new OpcodeOp("OP_NUMEQUAL"));
            e.accept(new SwapOp());
            e.accept(new PushOp(PushValue.ofHex(hexOf(new byte[want]))));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new PushOp(PushValue.of(want)));
            e.accept(new OpcodeOp("OP_SPLIT"));
            e.accept(new DropOp());
        });
        t.nm.add(flagName);
        t.nm.add(name);
    }

    private static void decomposePoint(ECTracker t, String pointName, String xName, String yName) {
        t.toTop(pointName);
        // OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top) — but only for
        // a value that really is 64 bytes. CL-BUG-095: gate the width first, here,
        // so every consumer that decomposes a Point inherits the check.
        t.rawBlock(List.of(pointName), "", e -> {
            emitPointLenVerify(e, 64);
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
        // The chord slope s = (qy - py) / (qx - px) is undefined when P == Q:
        // the denominator is zero and the correct slope is the TANGENT,
        // 3px^2 / (2py). Without this, ecAdd(P, P) silently produced a wrong
        // point, so every contract that doubled deployed an unspendable script.
        //
        // Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR
        // are selected and the single expensive fieldInv still runs once.
        // rx and ry below are already correct for doubling.
        //
        //   cond   = (px == qx) AND (py == qy)   1 when doubling, else 0
        //   num    = cond ? 3*px^2 : (qy - py)
        //   den    = cond ? 2*py   : (qx - px)
        //
        // selected as `b + cond*(a - b)`, which needs no branch and keeps the
        // emitted op sequence identical on both paths.
        //
        // THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx
        // ALONE sends it down the tangent path and returns 2P — an on-curve,
        // entirely plausible, WRONG point. Before the doubling fix the chord
        // path ran there, divided by zero (fieldInv is Fermat, inv(0) = 0) and
        // produced an OFF-curve blob, so `assert(ecOnCurve(ecAdd(a, b)))` —
        // the idiom this codegen tells authors to write — happened to reject
        // it. Selecting on px alone would have silently disarmed that.
        //
        // P + (-P) is the point at infinity, which affine x||y cannot
        // represent. This codegen already has a representation for O: the
        // ALL-ZERO blob, which is what `ecMul(P, 0n)` returns and what the
        // `ec-mulgen-linear` rewrite in optimizer/ec-rules.json produces for
        // k1 + k2 == 0 (mod n). So return that, by masking the result with
        // `notinf = NOT(px == qx AND NOT cond)`:
        //
        //   - it agrees with the rewrite, so the same source cannot give two
        //     answers depending on whether the optimizer fired;
        //   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate
        //     rejects it and the idiom above works again;
        //   - it adds no failure channel to what is a pure value-producing
        //     expression, the same reason emitScalarReduce reduces instead of
        //     rejecting.
        //
        // The mask is a bare OP_MUL with no reduction: rx, ry are already in
        // [0, p) and notinf is 0 or 1, so the product is canonical either way.
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
        // notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and
        // the points are not equal, i.e. exactly the P == -Q case.
        t.toTop("_xeq");
        t.copyToTop("_cond", "_cond_c");
        t.rawBlock(List.of("_xeq", "_cond_c"), "_notinf", e -> {
            e.accept(new OpcodeOp("OP_SUB"));
            e.accept(new OpcodeOp("OP_NOT"));
        });

        // chord numerator / denominator
        t.copyToTop("qy", "_qy1");
        t.copyToTop("py", "_py1");
        fieldSub(t, "_qy1", "_py1", "_num_chord");
        t.copyToTop("qx", "_qx1");
        t.copyToTop("px", "_px1");
        fieldSub(t, "_qx1", "_px1", "_den_chord");

        // tangent numerator / denominator: 3*px^2 and 2*py
        t.copyToTop("px", "_px_t");
        fieldSqr(t, "_px_t", "_px_sq");
        fieldMulConst(t, "_px_sq", 3, "_num_tan");
        t.copyToTop("py", "_py_t");
        fieldMulConst(t, "_py_t", 2, "_den_tan");

        // num = num_chord + cond*(num_tan - num_chord)
        t.copyToTop("_num_chord", "_num_chord_c");
        fieldSub(t, "_num_tan", "_num_chord_c", "_num_diff");
        t.copyToTop("_cond", "_cond_n");
        fieldMul(t, "_num_diff", "_cond_n", "_num_sel");
        fieldAdd(t, "_num_chord", "_num_sel", "_s_num");

        // den = den_chord + cond*(den_tan - den_chord)
        t.copyToTop("_den_chord", "_den_chord_c");
        fieldSub(t, "_den_tan", "_den_chord_c", "_den_diff");
        t.toTop("_cond");
        t.rename("_cond_d");
        fieldMul(t, "_den_diff", "_cond_d", "_den_sel");
        fieldAdd(t, "_den_chord", "_den_sel", "_s_den");

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

        // CL-BUG-096: select over the infinity operands and the P == -Q case, and
        // consume px/py/qx/qy in doing so. This subsumes the standalone `notinf`
        // mask that used to live here. See emitAffineInfinitySelect.
        emitAffineInfinitySelect(t);
    }

    /**
     * CL-BUG-096 — the infinity-operand case of affine addition, shared by
     * secp256k1 and the two NIST curves because it is pure integer masking and
     * touches no field parameter.
     *
     * <p>The group law has an identity, and this codegen has a representation for
     * it: the ALL-ZERO blob. It is not a theoretical value — the codegen
     * MANUFACTURES it, from {@code ecMul(P, k)} whenever k = 0 (mod n), from
     * affineAdd's own P + (-P) masking, and from the {@code ec-mul-zero} /
     * {@code ec-add-negate-cancel} rewrites in optimizer/ec-rules.json.
     * {@code affineAdd} nonetheless had no case for it: fed (G, O) it took the
     * chord path with s = Gy/Gx and returned an off-curve blob from a script that
     * SUCCEEDED.
     *
     * <p>And the always-on EC optimizer already believed the right answer:
     * {@code ec-add-identity-right} / {@code -left} rewrite
     * {@code ecAdd($x, INFINITY)} to {@code $x}. So the same source meant "P" with
     * the optimizer on and "garbage" with it off. Fixing the adder rather than
     * deleting the two rules is the only option that works, because the rules
     * cannot see a zero scalar that only exists at runtime.
     *
     * <p>Branch-free, in the style the rest of this adder uses. Exactly one of the
     * three masks is 1 and the other two are 0, so the sum selects one term:
     *
     * <pre>
     *   pinf = (px == 0) AND (py == 0)          P is O
     *   qinf = (qx == 0) AND (qy == 0)          Q is O
     *   usep = qinf AND NOT pinf                -&gt; answer is P
     *   useq = pinf                             -&gt; answer is Q  (covers O + O = O)
     *   user = notinf AND NOT(pinf OR qinf)     -&gt; answer is the computed sum
     * </pre>
     *
     * <p>{@code user} folds in the pre-existing {@code notinf} mask (the P == -Q
     * case), so P + (-P) still yields the all-zero blob and nothing about that case
     * changes.
     *
     * <p>Requiring BOTH coordinates to be zero is load-bearing, not
     * belt-and-braces. x = 0 has genuine curve points whenever the curve's b is a
     * quadratic residue — (0, sqrt(b)) — and testing x alone would map them to O.
     * y = 0 has none on any of these three curves (all have prime order, so no
     * point of order 2), but the conjunction makes that fact not need to be true.
     *
     * <p>Plain OP_MUL / OP_ADD with no field reduction: px, qx, rx are already in
     * [0, p) and the masks are 0 or 1, so each product and the sum are canonical.
     *
     * <p>Consumes px, py, qx, qy and the field-computed rx, ry; leaves the selected
     * rx, ry in their place.
     */
    public static void emitAffineInfinitySelect(ECTracker t) {
        // pinf = (px == 0) AND (py == 0)
        t.copyToTop("px", "_px_z");
        t.pushInt("_zero_px", 0);
        t.rawBlock(List.of("_px_z", "_zero_px"), "_pxz",
            e -> e.accept(new OpcodeOp("OP_NUMEQUAL")));
        t.copyToTop("py", "_py_z");
        t.pushInt("_zero_py", 0);
        t.rawBlock(List.of("_py_z", "_zero_py"), "_pyz",
            e -> e.accept(new OpcodeOp("OP_NUMEQUAL")));
        t.rawBlock(List.of("_pxz", "_pyz"), "_pinf",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));

        // qinf = (qx == 0) AND (qy == 0)
        t.copyToTop("qx", "_qx_z");
        t.pushInt("_zero_qx", 0);
        t.rawBlock(List.of("_qx_z", "_zero_qx"), "_qxz",
            e -> e.accept(new OpcodeOp("OP_NUMEQUAL")));
        t.copyToTop("qy", "_qy_z");
        t.pushInt("_zero_qy", 0);
        t.rawBlock(List.of("_qy_z", "_zero_qy"), "_qyz",
            e -> e.accept(new OpcodeOp("OP_NUMEQUAL")));
        t.rawBlock(List.of("_qxz", "_qyz"), "_qinf",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));

        // usep = qinf AND NOT pinf
        t.copyToTop("_qinf", "_usep_q");
        t.copyToTop("_pinf", "_usep_p");
        t.rawBlock(List.of("_usep_q", "_usep_p"), "_usep", e -> {
            e.accept(new OpcodeOp("OP_NOT"));
            e.accept(new OpcodeOp("OP_BOOLAND"));
        });

        // useq = pinf
        t.copyToTop("_pinf", "_useq");

        // user = notinf AND NOT(pinf OR qinf)
        t.toTop("_pinf");
        t.toTop("_qinf");
        t.rawBlock(List.of("_pinf", "_qinf"), "_anyinf",
            e -> e.accept(new OpcodeOp("OP_BOOLOR")));
        t.toTop("_notinf");
        t.toTop("_anyinf");
        t.rawBlock(List.of("_notinf", "_anyinf"), "_user", e -> {
            e.accept(new OpcodeOp("OP_NOT"));
            e.accept(new OpcodeOp("OP_BOOLAND"));
        });

        // rx = px*usep + qx*useq + rx*user
        t.toTop("px");
        t.copyToTop("_usep", "_usep_x");
        t.rawBlock(List.of("px", "_usep_x"), "_selx_p",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        t.toTop("qx");
        t.copyToTop("_useq", "_useq_x");
        t.rawBlock(List.of("qx", "_useq_x"), "_selx_q",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        t.toTop("rx");
        t.copyToTop("_user", "_user_x");
        t.rawBlock(List.of("rx", "_user_x"), "_selx_r",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        t.rawBlock(List.of("_selx_q", "_selx_r"), "_selx_qr",
            e -> e.accept(new OpcodeOp("OP_ADD")));
        t.rawBlock(List.of("_selx_p", "_selx_qr"), "rx",
            e -> e.accept(new OpcodeOp("OP_ADD")));

        // ry = py*usep + qy*useq + ry*user  (last use of each mask: consume them)
        t.toTop("py");
        t.toTop("_usep");
        t.rawBlock(List.of("py", "_usep"), "_sely_p",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        t.toTop("qy");
        t.toTop("_useq");
        t.rawBlock(List.of("qy", "_useq"), "_sely_q",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        t.toTop("ry");
        t.toTop("_user");
        t.rawBlock(List.of("ry", "_user"), "_sely_r",
            e -> e.accept(new OpcodeOp("OP_MUL")));
        t.rawBlock(List.of("_sely_q", "_sely_r"), "_sely_qr",
            e -> e.accept(new OpcodeOp("OP_ADD")));
        t.rawBlock(List.of("_sely_p", "_sely_qr"), "ry",
            e -> e.accept(new OpcodeOp("OP_ADD")));
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
        jacobianAddAffineBody(new ECTracker(t.nm, e), false);
    }

    /**
     * The mixed-add itself, emitting through an ECTracker the caller owns.
     *
     * <p>{@code keepHR} additionally leaves copies of H and R on the stack. They are the
     * exception detector: H = U2 - X1 and R = S2 - Y1 are both zero exactly when the
     * Jacobian accumulator is the same curve point as the affine operand, the one case
     * these formulas cannot compute (see buildJacobianAddOrDoubleInline).
     */
    private static void jacobianAddAffineBody(ECTracker it, boolean keepHR) {
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

        if (keepHR) {
            it.copyToTop("_H", "_H_keep");
            it.copyToTop("_R", "_R_keep");
        }

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

    /**
     * Branchless select of one Jacobian coordinate: {@code add + cond*(dbl - add)}.
     * Same shape as the numerator/denominator select in affineAdd, so both paths emit
     * the identical op sequence and the tracker's static stack model holds.
     * Consumes addName, dblName and condName.
     */
    private static void selectCoord(ECTracker t, String addName, String dblName,
                                    String condName, String resultName) {
        t.copyToTop(addName, "_sel_add_c");
        fieldSub(t, dblName, "_sel_add_c", "_sel_diff");
        fieldMul(t, "_sel_diff", condName, "_sel_scaled");
        fieldAdd(t, addName, "_sel_scaled", resultName);
    }

    /**
     * The ladder's LAST conditional step: mixed-add, but correct when the accumulator
     * already equals the point being added.
     *
     * <p>The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the two
     * operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at infinity —
     * and since fieldInv is Fermat (inv(0) = 0), jacobianToAffine turns that into the
     * ALL-ZERO point instead of 2P. {@code ecMul(P, 2n)} and {@code ecMulGen(2n)}
     * returned 64 zero bytes.
     *
     * <p>WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
     * c_i = k' &gt;&gt; i and k' = k + 3n, so the conditional step adds P to (c_i - 1)*P.
     * secp256k1 has cofactor 1, so P has order n and the degenerate cases are exactly
     * c_i == 2 (mod n) — accumulator == P — and c_i == 0 or 1 (mod n) — accumulator == -P
     * or O. c_i ranges over a CONTIGUOUS interval determined only by i, so this is
     * decidable by interval arithmetic rather than by sampling, and over the whole domain
     * k in [0, n-1] only two steps qualify, both at i = 0:
     *
     * <pre>
     *   k = 2  -&gt;  c_0 = 3n+2 == 2, odd, so the add runs: accumulator == P.  &lt;- bug
     *   k = 0  -&gt;  c_0 = 3n   == 0, odd, so the add runs: accumulator == -P,
     *              true result the point at infinity, which affine coordinates
     *              cannot represent; it stays the all-zero point, as before.
     * </pre>
     *
     * <p>At i &gt;= 1, c_i lies in [3n&gt;&gt;i, (4n-1)&gt;&gt;i] — the lower bound is 3n,
     * not 3n+1, because the reduce puts k = 0 in the domain — and that interval contains
     * no value == 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is even, so no add runs.
     * Handling H == 0 at every one of the 257 steps would cost ~70% more script bytes;
     * handling it here costs 0.26%. The operand P is caller-supplied but cannot move the
     * exception, because the condition depends only on c_i mod ord(P) and ord(P) = n for
     * every point on the curve. Points that are NOT on the curve carry no such guarantee —
     * gate untrusted input on {@code ecOnCurve} first.
     *
     * <p>THE ENTIRE ARGUMENT IS CONDITIONED ON k in [0, n-1], which is only true because
     * {@code emitEcMul} reduces k mod n before adding 3n. That reduce landed one commit
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
    private static void buildJacobianAddOrDoubleInline(Consumer<StackOp> e, ECTracker t) {
        ECTracker it = new ECTracker(t.nm, e);

        // Keep the pre-add accumulator: it is what must be DOUBLED in the
        // exceptional case, and the add below consumes jx/jy/jz.
        it.copyToTop("jx", "_sx");
        it.copyToTop("jy", "_sy");
        it.copyToTop("jz", "_sz");

        jacobianAddAffineBody(it, true);

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

        // Move the add result aside so jacobianDouble can work on jx/jy/jz again,
        // this time holding the saved accumulator.
        it.toTop("jx"); it.rename("_add_x");
        it.toTop("jy"); it.rename("_add_y");
        it.toTop("jz"); it.rename("_add_z");
        it.toTop("_sx"); it.rename("jx");
        it.toTop("_sy"); it.rename("jy");
        it.toTop("_sz"); it.rename("jz");
        jacobianDouble(it);
        it.toTop("jx"); it.rename("_dbl_x");
        it.toTop("jy"); it.rename("_dbl_y");
        it.toTop("jz"); it.rename("_dbl_z");

        it.copyToTop("_cond", "_cond_x");
        selectCoord(it, "_add_x", "_dbl_x", "_cond_x", "jx");
        it.copyToTop("_cond", "_cond_y");
        selectCoord(it, "_add_y", "_dbl_y", "_cond_y", "jy");
        it.toTop("_cond"); it.rename("_cond_z");
        selectCoord(it, "_add_z", "_dbl_z", "_cond_z", "jz");
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

    /**
     * Reduces a scalar to [0, n-1]: ((k mod n) + n) mod n.
     *
     * <p>OP_MOD takes the sign of the DIVIDEND, so {@code k mod n} alone lands in
     * (-n, n); the {@code + n, mod n} normalises the negative half. One push of n
     * covers both reductions — the same shape as {@code emitEcModReduce}.
     *
     * <p>Without it, {@link #emitEcMul}'s ladder is only correct while
     * 2^257 &lt;= k + 3n &lt; 2^258: a scalar &gt;= ~n sets bit 258, the
     * 257-iteration loop never sees it, and the ladder returns a DIFFERENT
     * multiple of P rather than failing. Scalars are contract input, so that is
     * attacker-chosen. Reducing costs 1 push + 8 opcodes (42 bytes) against a
     * ~429 KB script, and makes k &gt;= n, k &lt; 0 and k = 0 all well defined.
     */
    private static void emitScalarReduce(ECTracker t, String kName, String resultName) {
        t.pushBigInt("_n_red", EC_CURVE_N);
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

    public static void emitEcMul(Consumer<StackOp> emit) {
        ECTracker t = new ECTracker(List.of("_pt", "_k"), emit);
        decomposePoint(t, "_pt", "ax", "ay");

        // k' = k + 3n
        //
        // "k in [1, n-1]" is a PRECONDITION the caller cannot enforce — the scalar
        // is usually an unlock argument — so reduce it first.
        t.toTop("_k");
        emitScalarReduce(t, "_k", "_kr");
        t.pushBigInt("_n", EC_CURVE_N);
        t.rawBlock(List.of("_kr", "_n"), "_kn", e -> e.accept(new OpcodeOp("OP_ADD")));
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
            // Only the final step can be handed two equal operands — see
            // buildJacobianAddOrDoubleInline for why, and for what it costs not to.
            if (bit == 0) {
                buildJacobianAddOrDoubleInline(addOps::add, t);
            } else {
                buildJacobianAddAffineInline(addOps::add, t);
            }
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

        // CL-BUG-095: width. `ecOnCurve(G ‖ 0xff)` returned TRUE — decomposePoint
        // discarded the surplus byte, so 2^8 distinct blobs all certified as the
        // same point and a point's identity AS BYTES stopped being unique. Clamp and
        // remember the width, rather than abort, because this is the predicate
        // contracts are told to gate untrusted points on and it must stay total; the
        // flag is ANDed into the result at the end.
        emitPointLengthGate(t, "_pt", 64, "_len_ok");

        decomposePoint(t, "_pt", "_x", "_y");

        // GAP-301: coordinate canonicity. decomposePoint BIN2NUMs each coordinate
        // as an unsigned value that may be >= p; the field arithmetic below would
        // silently reduce it mod p, so a non-canonical encoding of a valid point
        // would pass. Reject it: require x < p AND y < p (coordinates are unsigned,
        // so the 0 <= lower bound holds by construction). Combined with the curve
        // equation at the end via OP_BOOLAND so ecOnCurve still returns a boolean.
        t.copyToTop("_x", "_x_lt");
        pushFieldP(t, "_p_for_x");
        t.rawBlock(List.of("_x_lt", "_p_for_x"), "_x_canon",
            e -> e.accept(new OpcodeOp("OP_LESSTHAN")));
        t.copyToTop("_y", "_y_lt");
        pushFieldP(t, "_p_for_y");
        t.rawBlock(List.of("_y_lt", "_p_for_y"), "_y_canon",
            e -> e.accept(new OpcodeOp("OP_LESSTHAN")));
        t.toTop("_x_canon");
        t.toTop("_y_canon");
        t.rawBlock(List.of("_x_canon", "_y_canon"), "_canon",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));

        // lhs = y^2
        fieldSqr(t, "_y", "_y2");

        // rhs = x^3 + 7
        t.copyToTop("_x", "_x_copy");
        fieldSqr(t, "_x", "_x2");
        fieldMul(t, "_x2", "_x_copy", "_x3");
        t.pushInt("_seven", 7);
        fieldAdd(t, "_x3", "_seven", "_rhs");

        // Compare curve equation
        t.toTop("_y2");
        t.toTop("_rhs");
        t.rawBlock(List.of("_y2", "_rhs"), "_curve_eq",
            e -> e.accept(new OpcodeOp("OP_EQUAL")));

        // on-curve = right width AND canonical AND curve-equation
        t.toTop("_canon");
        t.toTop("_curve_eq");
        t.rawBlock(List.of("_canon", "_curve_eq"), "_eq_ok",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
        t.toTop("_len_ok");
        t.toTop("_eq_ok");
        t.rawBlock(List.of("_len_ok", "_eq_ok"), "_result",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
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
        // CL-BUG-095, and the reason this one is the sharpest edge of it: the parity
        // byte used to be taken from the blob's LAST byte (OP_SIZE 1 OP_SUB
        // OP_SPLIT), not from a fixed offset. So appending one byte FLIPPED THE SIGN
        // of the compressed encoding — the same 64-byte point compressed to 02‖x or
        // 03‖x at the caller's choice, and anything that hashes a compressed pubkey
        // (a P2PKH address, a commitment) became forgeable between the two
        // spellings. Two independent fixes, both kept: the width is verified, and
        // the parity byte is read from offset 31 of y whatever the caller sent.
        emitPointLenVerify(emit, 64);
        // Split at 32: [x_bytes, y_bytes]
        emit.accept(new PushOp(PushValue.of(32)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        // Take y[31] at a FIXED offset: [x_bytes, y_head, y_last]
        emit.accept(new PushOp(PushValue.of(31)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new OpcodeOp("OP_NIP")); // drop y_head
        // Stack: [x_bytes, last_byte]
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
        emit.accept(new PushOp(PushValue.of(2)));
        emit.accept(new OpcodeOp("OP_MOD"));
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
        // CL-BUG-095: a 32-byte blob used to SUCCEED here and return itself as x —
        // the split at 32 left an empty tail that `drop` happily removed. ecPointY
        // on the identical input already aborted, which is how the hole survived: a
        // short point looked "already rejected".
        emitPointLenVerify(emit, 64);
        emit.accept(new PushOp(PushValue.of(32)));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new DropOp());
        emitReverse32(emit);
        emit.accept(new PushOp(PushValue.ofHex("00")));
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
    }

    public static void emitEcPointY(Consumer<StackOp> emit) {
        emitPointLenVerify(emit, 64);
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
