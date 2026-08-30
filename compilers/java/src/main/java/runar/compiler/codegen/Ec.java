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

    /**
     * Codegen options shared by every EC / NIST-curve emitter.
     *
     * <p>Off by default: with {@code null} (or an all-false instance) each emitter is byte-identical
     * to what the seven tiers ship today, so no golden, size baseline, or cross-tier parity gate can
     * move.
     *
     * @param constantPool park large repeated constants (the field prime, the group order) in a
     *     stack slot and copy them with {@code OP_PICK} instead of re-pushing the literal. {@code
     *     fieldMod} pushes the 256-bit prime at every modular reduction — 34 bytes a time, 20,025
     *     times in {@code p256-wallet} (71 % of that fixture). A pick from a slot a dozen deep costs
     *     2.
     * @param reductionSinking emit {@code a mod p} without the sign fix-up wherever the dividend is
     *     provably non-negative, and the cheap {@code a - b + p} form for subtraction wherever the
     *     subtrahend is provably reduced. Which reductions qualify is decided by the sign lattice
     *     below — never assumed. Only useful alongside {@code constantPool}: the cheap subtraction
     *     references the prime twice, so without a pooled slot it does not pay (and the emitters
     *     compare the two costs, so it is never taken when it does not).
     * @param fixedBaseComb use a fixed-base comb instead of the binary ladder wherever the base
     *     point is a compile-time constant. The window width is not fixed here: the emitter renders
     *     each candidate and keeps whichever the byte-cost model scores smallest.
     */
    public record EcCodegenOptions(
            boolean constantPool, boolean reductionSinking, boolean fixedBaseComb) {

        /** All flags off — byte-identical to the shipping output. */
        public static EcCodegenOptions none() {
            return new EcCodegenOptions(false, false, false);
        }
    }

    /**
     * What is known about a tracked value's sign and range.
     *
     * <p>{@code REDUCED} implies {@code NON_NEGATIVE}; the ordering is what the transfer functions
     * meet over. {@code UNKNOWN} is the default for every slot the analysis has not explicitly proved
     * something about — including everything a {@code rawBlock} or an {@code OP_IF} produces — so an
     * un-analysed value can only ever fall back to the shipping reduction.
     *
     * <p>The distinction is not academic. {@code OP_BIN2NUM} of 32 unsigned coordinate bytes gives
     * {@code NON_NEGATIVE} but NOT {@code REDUCED}: a coordinate may legitimately be up to {@code
     * 2^256 - 1} while p is {@code 2^32 + 977} smaller. Multiplication and addition need only {@code
     * NON_NEGATIVE}; subtraction's cheap form needs the subtrahend {@code REDUCED}, and conflating
     * the two produces a script that passes 256 EC oracle assertions and is still wrong on {@code
     * ecAdd((0,1), (2^256-1,1))}.
     */
    public enum Dom {
        /** Nothing known. May be negative. */
        UNKNOWN,
        /** Provably &gt;= 0. May be &gt;= p. */
        NON_NEGATIVE,
        /** Provably in [0, p). */
        REDUCED;

        /** True when this proves the value is &gt;= 0. */
        boolean isNonNegative() {
            return this != UNKNOWN;
        }
    }

    /** Stack slot names reserved for pooled constants. */
    public static final String POOL_FIELD_P = "_pool$p";

    public static final String POOL_GROUP_N = "_pool$n";

    static final class ECTracker {
        final List<String> nm;
        /**
         * Sign-lattice fact per stack SLOT, kept parallel to {@link #nm}.
         *
         * <p>Slot-parallel rather than keyed by name on purpose: names are reused ({@code
         * _fmul_prod} is written by every multiply) and the same name can be resident twice, so a
         * name-keyed map would go stale in exactly the cases that matter. Every mutation of {@code
         * nm} below mirrors into {@code dm} with the same splice, so the two cannot drift.
         */
        final List<Dom> dm;

        /** Lattice facts for values parked on the alt stack, bottom -&gt; top. */
        private final List<Dom> altDm = new ArrayList<>();

        final Consumer<StackOp> e;
        /** True when this tracker may serve constants from a pooled slot. */
        final boolean pooling;
        /** True when this tracker may emit sunk reductions. */
        final boolean sinking;
        /** True when a compile-time-known base may use a fixed-base comb. */
        final boolean comb;

        ECTracker(List<String> init, Consumer<StackOp> emit) {
            this(init, emit, null, null);
        }

        ECTracker(List<String> init, Consumer<StackOp> emit, EcCodegenOptions opts,
                  List<Dom> initDomains) {
            this.nm = new ArrayList<>(init);
            this.dm = new ArrayList<>();
            if (initDomains != null) {
                this.dm.addAll(initDomains);
            } else {
                for (int i = 0; i < this.nm.size(); i++) this.dm.add(Dom.UNKNOWN);
            }
            this.e = emit;
            this.pooling = opts != null && opts.constantPool();
            this.sinking = opts != null && opts.reductionSinking();
            this.comb = opts != null && opts.fixedBaseComb();
        }

        /** The options this tracker was built with, for handing to a nested tracker. */
        EcCodegenOptions options() {
            return new EcCodegenOptions(pooling, sinking, comb);
        }

        // -- sign lattice ------------------------------------------------

        /** What is known about the named value. {@code UNKNOWN} when the name is absent. */
        Dom domainOf(String name) {
            // A silent desync here would hand a transfer function a fact about
            // the WRONG slot, which is the one failure mode that produces a
            // smaller script that quietly computes something else. Fail loudly.
            if (dm.size() != nm.size()) {
                throw new RuntimeException(
                        "ECTracker: lattice desynchronised (" + nm.size() + " slots, " + dm.size()
                                + " facts). Every nm mutation must go through a tracker method"
                                + " or pushTracked/popTracked.");
            }
            for (int i = nm.size() - 1; i >= 0; i--) {
                if (name.equals(nm.get(i))) return dm.get(i);
            }
            return Dom.UNKNOWN;
        }

        /** Record a fact about the named value's slot. */
        void setDomain(String name, Dom d) {
            for (int i = nm.size() - 1; i >= 0; i--) {
                if (name.equals(nm.get(i))) {
                    dm.set(i, d);
                    return;
                }
            }
        }

        /** Push a slot the caller tracks itself (used where raw opcodes create items). */
        void pushTracked(String name, Dom d) {
            nm.add(name);
            dm.add(d);
        }

        /** Pop a slot the caller tracks itself. Mirror of {@link #pushTracked}. */
        String popTracked() {
            if (nm.isEmpty()) return "";
            dm.remove(dm.size() - 1);
            return nm.remove(nm.size() - 1);
        }

        /** Remove the slot at an absolute (bottom-relative) index. */
        void removeSlotAt(int index) {
            nm.remove(index);
            dm.remove(index);
        }

        int depth() {
            return nm.size();
        }

        int findDepth(String name) {
            for (int i = nm.size() - 1; i >= 0; i--) {
                if (name.equals(nm.get(i))) return nm.size() - 1 - i;
            }
            throw new RuntimeException("ECTracker: '" + name + "' not on stack " + nm);
        }

        void pushBytes(String n, byte[] v) {
            e.accept(new PushOp(PushValue.ofHex(hexOf(v))));
            // A byte blob is not a number until BIN2NUM decides how to read it.
            pushTracked(n, Dom.UNKNOWN);
        }

        void pushBigInt(String n, BigInteger v) {
            e.accept(new PushOp(PushValue.of(v)));
            pushTracked(n, v.signum() >= 0 ? Dom.NON_NEGATIVE : Dom.UNKNOWN);
        }

        void pushInt(String n, long v) {
            e.accept(new PushOp(PushValue.of(v)));
            pushTracked(n, v >= 0 ? Dom.NON_NEGATIVE : Dom.UNKNOWN);
        }

        void dup(String n) {
            e.accept(new DupOp());
            pushTracked(n, dm.isEmpty() ? Dom.UNKNOWN : dm.get(dm.size() - 1));
        }

        void drop() {
            e.accept(new DropOp());
            popTracked();
        }

        void nip() {
            e.accept(new NipOp());
            int L = nm.size();
            if (L >= 2) removeSlotAt(L - 2);
        }

        void over(String n) {
            e.accept(new OverOp());
            pushTracked(n, dm.size() >= 2 ? dm.get(dm.size() - 2) : Dom.UNKNOWN);
        }

        void swap() {
            e.accept(new SwapOp());
            int L = nm.size();
            if (L >= 2) {
                String t = nm.get(L - 1);
                nm.set(L - 1, nm.get(L - 2));
                nm.set(L - 2, t);
                Dom d = dm.get(L - 1);
                dm.set(L - 1, dm.get(L - 2));
                dm.set(L - 2, d);
            }
        }

        void rot() {
            e.accept(new RotOp());
            int L = nm.size();
            if (L >= 3) {
                String r = nm.get(L - 3);
                Dom rd = dm.get(L - 3);
                removeSlotAt(L - 3);
                pushTracked(r, rd);
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
            pushTracked("", Dom.NON_NEGATIVE);
            e.accept(new RollOp(d));
            popTracked(); // the depth literal
            int idx = nm.size() - 1 - d;
            String r = nm.get(idx);
            Dom rd = dm.get(idx);
            removeSlotAt(idx);
            pushTracked(r, rd);
        }

        void pick(int d, String n) {
            if (d == 0) { dup(n); return; }
            if (d == 1) { over(n); return; }
            e.accept(new PushOp(PushValue.of(d)));
            pushTracked("", Dom.NON_NEGATIVE);
            e.accept(new PickOp(d));
            popTracked(); // the depth literal
            // Once the depth literal is gone the copied slot sits at depth d.
            Dom src = dm.size() > d ? dm.get(dm.size() - 1 - d) : Dom.UNKNOWN;
            pushTracked(n, src);
        }

        void toTop(String name) {
            roll(findDepth(name));
        }

        void copyToTop(String name, String n) {
            pick(findDepth(name), n);
        }

        // -- constant pool -----------------------------------------------
        //
        // A pooled constant is an ordinary tracked slot; nothing about the
        // stack model changes. pushConst just chooses, per call site and by
        // emitted bytes, between copying that slot and re-pushing the literal.
        // Nested trackers built from a copy of nm inherit the slot for free, so
        // pooled constants work unchanged inside an OP_IF arm.

        /** Park {@code value} in {@code slot} for this emitter. No-op when pooling is off. */
        void poolConstant(String slot, BigInteger value) {
            if (!pooling || nm.contains(slot)) return;
            pushBigInt(slot, value);
        }

        /** Remove a pooled slot. No-op when pooling is off or the slot is absent. */
        void releaseConstant(String slot) {
            if (!pooling || !nm.contains(slot)) return;
            toTop(slot);
            drop();
        }

        /**
         * Emitted bytes a {@code pushConst} of this constant would cost right now.
         *
         * <p>The comparison is exact — {@code CostModel.sizeOfPushInt} is the same encoder the emit
         * pass uses — so pooling can never make a call site bigger. A pick at depth d costs {@code
         * sizeOfPushInt(d) + 1}; depths 0 and 1 are OP_DUP / OP_OVER, 1 byte each.
         */
        int constCost(String slot, BigInteger value) {
            if (pooling && nm.contains(slot)) {
                int d = findDepth(slot);
                int pickCost =
                        d <= 1 ? 1 : CostModel.sizeOfPushInt(BigInteger.valueOf(d)) + 1;
                if (pickCost < CostModel.sizeOfPushInt(value)) return pickCost;
            }
            return CostModel.sizeOfPushInt(value);
        }

        /**
         * Materialize {@code value} on top as {@code name}, from the pooled slot when that is cheaper
         * in emitted bytes than pushing the literal.
         */
        void pushConst(String slot, BigInteger value, String name) {
            if (pooling && nm.contains(slot)) {
                int d = findDepth(slot);
                int pickCost =
                        d <= 1 ? 1 : CostModel.sizeOfPushInt(BigInteger.valueOf(d)) + 1;
                if (pickCost < CostModel.sizeOfPushInt(value)) {
                    pick(d, name);
                    return;
                }
            }
            pushBigInt(name, value);
        }

        void toAlt() {
            op("OP_TOALTSTACK");
            if (!nm.isEmpty()) {
                Dom d = dm.get(dm.size() - 1);
                popTracked();
                altDm.add(d);
            }
        }

        void fromAlt(String n) {
            op("OP_FROMALTSTACK");
            Dom d = altDm.isEmpty() ? Dom.UNKNOWN : altDm.remove(altDm.size() - 1);
            pushTracked(n, d);
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
                popTracked();
            }
            fn.accept(this.e);
            if (produce != null && !produce.isEmpty()) {
                // Opaque opcodes: nothing is known about the result unless the
                // caller proves it and records that with setDomain afterwards.
                pushTracked(produce, Dom.UNKNOWN);
            }
        }

        /** Emit if/else with tracked stack effect. resultName="" => no result. */
        void emitIf(String condName,
                    Consumer<Consumer<StackOp>> thenFn,
                    Consumer<Consumer<StackOp>> elseFn,
                    String resultName) {
            toTop(condName);
            popTracked(); // condition consumed
            List<StackOp> thenOps = new ArrayList<>();
            List<StackOp> elseOps = new ArrayList<>();
            thenFn.accept(thenOps::add);
            elseFn.accept(elseOps::add);
            this.e.accept(new IfOp(thenOps, elseOps));
            if (resultName != null && !resultName.isEmpty()) {
                // A join over two arms this tracker did not analyse: nothing is known.
                pushTracked(resultName, Dom.UNKNOWN);
            }
        }
    }

    // ==================================================================
    // Field arithmetic helpers (mod p)
    // ==================================================================

    private static void pushFieldP(ECTracker t, String name) {
        t.pushConst(POOL_FIELD_P, EC_FIELD_P, name);
    }

    /**
     * {@code a mod p} with no sign fix-up: 1 opcode instead of 7.
     *
     * <p>Sound only when the dividend is provably &gt;= 0, because {@code OP_MOD} takes the sign of
     * the dividend. The caller proves that; this function does not check.
     */
    private static void fieldModShort(ECTracker t, String aName, String resultName) {
        t.toTop(aName);
        pushFieldP(t, "_fmods_p");
        t.rawBlock(List.of(aName, "_fmods_p"), resultName,
                e -> e.accept(new OpcodeOp("OP_MOD")));
        t.setDomain(resultName, Dom.REDUCED);
    }

    /**
     * Does the cheap {@code a - b + p} subtraction shape pay here?
     *
     * <p>It references the prime TWICE where the shipping shape references it once and pays six more
     * opcodes, so it only wins when the prime is cheap to materialise — i.e. when it is pooled.
     * Without a pool this rewrite makes p256-wallet LARGER (958,792 -&gt; 999,371 measured), which is
     * why it is a cost comparison and not a flag.
     */
    private static boolean cheapSubPays(ECTracker t) {
        int c = t.constCost(POOL_FIELD_P, EC_FIELD_P);
        return 2 * c + 2 < c + 8;
    }

    private static void fieldMod(ECTracker t, String aName, String resultName) {
        if (t.sinking && t.domainOf(aName).isNonNegative()) {
            fieldModShort(t, aName, resultName);
            return;
        }
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
        t.setDomain(resultName, Dom.REDUCED);
    }

    private static void fieldAdd(ECTracker t, String aName, String bName, String resultName) {
        // Read the operand facts BEFORE rawBlock consumes their slots.
        boolean sumNonNeg =
                t.domainOf(aName).isNonNegative() && t.domainOf(bName).isNonNegative();
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fadd_sum", e -> e.accept(new OpcodeOp("OP_ADD")));
        if (sumNonNeg) t.setDomain("_fadd_sum", Dom.NON_NEGATIVE);
        fieldMod(t, "_fadd_sum", resultName);
    }

    private static void fieldSub(ECTracker t, String aName, String bName, String resultName) {
        t.toTop(aName);
        t.toTop(bName);
        // The cheap shape needs a >= 0 AND b in [0, p): then a - b > -p, so a
        // single shifted reduction is exact. `b >= 0` alone is NOT enough — a
        // coordinate decoded from 32 unsigned bytes can exceed p by up to
        // 2^32 + 977, which is precisely the ecAdd((0,1), (2^256-1,1))
        // counterexample.
        boolean cheap =
                t.sinking
                        && t.domainOf(aName).isNonNegative()
                        && t.domainOf(bName) == Dom.REDUCED
                        && cheapSubPays(t);

        t.rawBlock(List.of(aName, bName), "_fsub_diff", e -> e.accept(new OpcodeOp("OP_SUB")));

        if (cheap) {
            pushFieldP(t, "_fsub_p");
            t.rawBlock(List.of("_fsub_diff", "_fsub_p"), "_fsub_shift",
                    e -> e.accept(new OpcodeOp("OP_ADD")));
            t.setDomain("_fsub_shift", Dom.NON_NEGATIVE);
            fieldModShort(t, "_fsub_shift", resultName);
            return;
        }
        fieldMod(t, "_fsub_diff", resultName);
    }

    private static void fieldMul(ECTracker t, String aName, String bName, String resultName) {
        fieldMul(t, aName, bName, resultName, false);
    }

    /**
     * {@code fieldMul} with an explicit assertion about the product's sign, independent of the
     * operands — {@code fieldSqr} uses it, since a*a &gt;= 0 for any a whatsoever.
     */
    private static void fieldMul(ECTracker t, String aName, String bName, String resultName,
                                 boolean productNonNegative) {
        boolean nonNeg =
                productNonNegative
                        || (t.domainOf(aName).isNonNegative()
                                && t.domainOf(bName).isNonNegative());
        t.toTop(aName);
        t.toTop(bName);
        t.rawBlock(List.of(aName, bName), "_fmul_prod", e -> e.accept(new OpcodeOp("OP_MUL")));
        if (nonNeg) t.setDomain("_fmul_prod", Dom.NON_NEGATIVE);
        fieldMod(t, "_fmul_prod", resultName);
    }

    private static void fieldMulConst(ECTracker t, String aName, long c, String resultName) {
        // Every call site passes a small positive c, so the product keeps a's sign.
        boolean nonNeg = c > 0 && t.domainOf(aName).isNonNegative();
        t.toTop(aName);
        t.rawBlock(List.of(aName), "_fmc_prod", e -> {
            if (c == 2L) {
                e.accept(new OpcodeOp("OP_2MUL"));
            } else {
                e.accept(new PushOp(PushValue.of(c)));
                e.accept(new OpcodeOp("OP_MUL"));
            }
        });
        if (nonNeg) t.setDomain("_fmc_prod", Dom.NON_NEGATIVE);
        fieldMod(t, "_fmc_prod", resultName);
    }

    /** {@code (a * a) mod p}. A square is non-negative whatever a's sign is. */
    private static void fieldSqr(ECTracker t, String aName, String resultName) {
        t.copyToTop(aName, "_fsqr_copy");
        fieldMul(t, aName, "_fsqr_copy", resultName, true);
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

    private static void decomposePoint(ECTracker t, String pointName, String xName, String yName) {
        t.toTop(pointName);
        t.rawBlock(List.of(pointName), "", e -> {
            e.accept(new PushOp(PushValue.of(32)));
            e.accept(new OpcodeOp("OP_SPLIT"));
        });
        // Manually track the two new items
        t.pushTracked("_dp_xb", Dom.UNKNOWN);
        t.pushTracked("_dp_yb", Dom.UNKNOWN);

        // Convert y_bytes (on top) to num
        t.rawBlock(List.of("_dp_yb"), yName, e -> {
            emitReverse32(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });
        // A 0x00 sign byte is appended before BIN2NUM, so the coordinate
        // decodes UNSIGNED: >= 0, but it may be up to 2^(8*coordBytes) - 1 and
        // therefore >= p. That gap is exactly what the subtraction precondition
        // turns on.
        t.setDomain(yName, Dom.NON_NEGATIVE);

        // Convert x_bytes to num
        t.toTop("_dp_xb");
        t.rawBlock(List.of("_dp_xb"), xName, e -> {
            emitReverse32(e);
            e.accept(new PushOp(PushValue.ofHex("00")));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
        });
        t.setDomain(xName, Dom.NON_NEGATIVE);

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
        // The inner tracker inherits the stack state AND the lattice facts: the
        // operands' proved domains are what decide which reduction shape the
        // body emits, so dropping them here would silently fall back everywhere.
        jacobianAddAffineBody(new ECTracker(t.nm, e, t.options(), t.dm), false);
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
        ECTracker it = new ECTracker(t.nm, e, t.options(), t.dm);

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
        emitEcAdd(emit, null);
    }

    public static void emitEcAdd(Consumer<StackOp> emit, EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pa", "_pb"), emit, opts, null);
        t.poolConstant(POOL_FIELD_P, EC_FIELD_P);
        decomposePoint(t, "_pa", "px", "py");
        decomposePoint(t, "_pb", "qx", "qy");
        affineAdd(t);
        composePoint(t, "rx", "ry", "_result");
        t.releaseConstant(POOL_FIELD_P);
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
        t.pushConst(POOL_GROUP_N, EC_CURVE_N, "_n_red");
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
        emitEcMul(emit, null);
    }

    public static void emitEcMul(Consumer<StackOp> emit, EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pt", "_k"), emit, opts, null);
        t.poolConstant(POOL_FIELD_P, EC_FIELD_P);
        t.poolConstant(POOL_GROUP_N, EC_CURVE_N);
        decomposePoint(t, "_pt", "ax", "ay");

        // k' = k + 3n
        //
        // "k in [1, n-1]" is a PRECONDITION the caller cannot enforce — the scalar
        // is usually an unlock argument — so reduce it first.
        t.toTop("_k");
        emitScalarReduce(t, "_k", "_kr");
        t.pushConst(POOL_GROUP_N, EC_CURVE_N, "_n");
        t.rawBlock(List.of("_kr", "_n"), "_kn", e -> e.accept(new OpcodeOp("OP_ADD")));
        t.pushConst(POOL_GROUP_N, EC_CURVE_N, "_n2");
        t.rawBlock(List.of("_kn", "_n2"), "_kn2", e -> e.accept(new OpcodeOp("OP_ADD")));
        t.pushConst(POOL_GROUP_N, EC_CURVE_N, "_n3");
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
            t.popTracked(); // _bit consumed by IF
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
        t.releaseConstant(POOL_GROUP_N);
        t.releaseConstant(POOL_FIELD_P);
    }

    // ==================================================================
    // Fixed-base comb (secp256k1)
    // ==================================================================

    /**
     * Round {@code i}'s digit and the selected table entry, as {@code ax}/{@code ay}/{@code _flag}.
     *
     * <p>Exactly one equality holds, so {@code sum(eq_j * T_j)} is that entry's coordinate and every
     * term is non-negative and below p — no reduction is needed, and the result is {@code REDUCED} by
     * construction. When the digit is zero every term vanishes and {@code _flag} is 0, so no add
     * runs.
     *
     * <p>Shared by both comb emitters: the selection is pure scalar bit-twiddling and table indexing,
     * with no curve arithmetic in it at all.
     */
    static void combEmitSelect(ECTracker t, int i, int w, int d) {
        int entries = (1 << w) - 1;
        for (int b = 0; b < w; b++) {
            int shift = i + b * d;
            String kc = "_kc" + b;
            String sh = "_sh" + b;
            t.copyToTop("_k", kc);
            if (shift == 0) {
                t.rename(sh);
            } else if (shift == 1) {
                t.rawBlock(List.of(kc), sh, e -> e.accept(new OpcodeOp("OP_2DIV")));
            } else {
                String sd = "_sd" + b;
                t.pushInt(sd, shift);
                t.rawBlock(List.of(kc, sd), sh, e -> e.accept(new OpcodeOp("OP_RSHIFTNUM")));
            }
            String two = "_two" + b;
            String bit = "_b" + b;
            t.pushInt(two, 2);
            t.rawBlock(List.of(sh, two), bit, e -> e.accept(new OpcodeOp("OP_MOD")));
            t.setDomain(bit, Dom.REDUCED);
        }

        t.toTop("_b0");
        t.rename("_idx");
        for (int b = 1; b < w; b++) {
            String bit = "_b" + b;
            String wt = "_wt" + b;
            String bw = "_bw" + b;
            t.toTop(bit);
            t.pushInt(wt, 1L << b);
            t.rawBlock(List.of(bit, wt), bw, e -> e.accept(new OpcodeOp("OP_MUL")));
            t.toTop("_idx");
            t.rawBlock(List.of(bw, "_idx"), "_idx", e -> e.accept(new OpcodeOp("OP_ADD")));
        }
        t.setDomain("_idx", Dom.REDUCED);

        for (int j = 1; j <= entries; j++) {
            String ic = "_ic" + j;
            String jv = "_jv" + j;
            String eq = "_eq" + j;
            t.copyToTop("_idx", ic);
            t.pushInt(jv, j);
            t.rawBlock(List.of(ic, jv), eq, e -> e.accept(new OpcodeOp("OP_NUMEQUAL")));
            t.setDomain(eq, Dom.REDUCED);
        }

        for (String coord : new String[] {"x", "y"}) {
            String acc = coord.equals("x") ? "ax" : "ay";
            for (int j = 1; j <= entries; j++) {
                String ec = "_e" + coord + j;
                String tc = "_t" + coord + j;
                String pr = "_pr" + coord + j;
                t.copyToTop("_eq" + j, ec);
                t.copyToTop("_T" + coord + j, tc);
                t.rawBlock(List.of(ec, tc), pr, e -> e.accept(new OpcodeOp("OP_MUL")));
                if (j == 1) {
                    t.rename(acc);
                } else {
                    t.toTop(acc);
                    t.rawBlock(List.of(pr, acc), acc, e -> e.accept(new OpcodeOp("OP_ADD")));
                }
            }
            t.setDomain(acc, Dom.REDUCED);
        }

        for (int j = entries; j >= 1; j--) {
            t.toTop("_eq" + j);
            t.drop();
        }

        t.toTop("_idx");
        t.rawBlock(List.of("_idx"), "_flag", e -> e.accept(new OpcodeOp("OP_0NOTEQUAL")));
    }

    /**
     * {@code k*G} by a Lim-Lee fixed-base comb instead of the 257-round binary ladder.
     *
     * <p>The ladder doubles and conditionally adds once per SCALAR BIT. A comb splits the scalar into
     * {@code w} blocks of {@code d} bits and reads one bit from each block per round, so it performs
     * one doubling and one conditional add per COLUMN: the round count falls from {@code w*d} to
     * {@code d} at the price of a {@code 2^w - 1} entry table. G is a compile-time constant here, so
     * the table costs nothing to build.
     *
     * <p>This is the secp256k1 twin of {@code P256P384.cEmitCombMulGen}. The curve arithmetic is NOT
     * shared: secp256k1 has {@code a = 0}, so {@code jacobianDouble} computes {@code D = 3X^2} where
     * the NIST version computes {@code 3(X-Z^2)(X+Z^2)}. Only {@code Comb} — the compile-time table
     * and the interval checker — is common, and it takes {@code a} from the curve record.
     *
     * <p>SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add accumulator equal to the
     * addend, its negation, or the point at infinity. {@code buildJacobianAddOrDoubleInline}'s comment
     * justifies using it everywhere but the ladder's LAST step by an interval argument over {@code c_i
     * mod n}, and insists that argument be re-derived by anything changing the offset or the iteration
     * count. A comb changes both, so it is re-derived: {@code Comb.combSafeRounds} evaluates the same
     * argument as executable interval arithmetic over the comb's own geometry, and any round it cannot
     * prove gets the complete add-or-double form instead. Nothing is assumed safe.
     *
     * <p>The other half of that argument is that the accumulator never starts at infinity, which needs
     * the first digit non-zero. {@code Comb.combGeometry} searches for the scalar offset that
     * guarantees it rather than reusing the ladder's hardcoded {@code +3n} — right for secp256k1 at
     * w=3, wrong for P-384.
     *
     * <p>Stack in: [_k]. Stack out: [_result].
     *
     * @return false when no geometry exists for {@code w}
     */
    private static boolean emitCombMulGen(Consumer<StackOp> emit, int w, EcCodegenOptions opts) {
        Comb.Curve curve = Comb.SECP256K1_COMB_CURVE;
        Comb.Params params = Comb.combGeometry(w, curve);
        if (params == null) return false;
        int d = params.d();
        List<Comb.Point> table = Comb.combTable(w, d, curve);
        boolean[] safe = Comb.combSafeRounds(params, curve);
        int entries = (1 << w) - 1;

        ECTracker t = new ECTracker(List.of("_k"), emit, opts, null);
        t.poolConstant(POOL_FIELD_P, EC_FIELD_P);
        t.poolConstant(POOL_GROUP_N, EC_CURVE_N);

        // k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so
        // what makes the interval argument apply at all; see emitScalarReduce.
        t.toTop("_k");
        emitScalarReduce(t, "_k", "_kr");
        t.rename("_k");
        for (int i = 0; i < params.offsetMultiple(); i++) {
            String off = "_off" + i;
            t.pushConst(POOL_GROUP_N, EC_CURVE_N, off);
            t.rawBlock(List.of("_k", off), "_k", e -> e.accept(new OpcodeOp("OP_ADD")));
        }
        t.setDomain("_k", Dom.NON_NEGATIVE);

        // Table, resident for the whole comb: picking an entry costs 2-3 bytes
        // against a 34-byte literal push, and every round reads all of them.
        for (int j = 1; j <= entries; j++) {
            Comb.Point pt = table.get(j);
            t.pushBigInt("_Tx" + j, pt.x());
            t.pushBigInt("_Ty" + j, pt.y());
            t.setDomain("_Tx" + j, Dom.REDUCED);
            t.setDomain("_Ty" + j, Dom.REDUCED);
        }

        // Round d-1 initialises the accumulator. The first digit is non-zero by
        // construction (combGeometry), so this is a real point, never infinity.
        combEmitSelect(t, d - 1, w, d);
        t.toTop("_flag");
        t.drop();
        t.toTop("ax");
        t.rename("jx");
        t.toTop("ay");
        t.rename("jy");
        t.pushInt("jz", 1);
        t.setDomain("jz", Dom.REDUCED);

        for (int i = d - 2; i >= 0; i--) {
            jacobianDouble(t);
            combEmitSelect(t, i, w, d);

            // jacobianAddAffineBody documents its layout as
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
                buildJacobianAddAffineInline(addOps::add, t);
            } else {
                buildJacobianAddOrDoubleInline(addOps::add, t);
            }
            emit.accept(new IfOp(addOps, List.of()));

            // The addend was selected fresh for this round; the add only copied it.
            t.toTop("ay");
            t.drop();
            t.toTop("ax");
            t.drop();
        }

        jacobianToAffine(t, "_rx", "_ry");

        for (int j = entries; j >= 1; j--) {
            t.toTop("_Ty" + j);
            t.drop();
            t.toTop("_Tx" + j);
            t.drop();
        }
        t.toTop("_k");
        t.drop();

        composePoint(t, "_rx", "_ry", "_result");
        t.releaseConstant(POOL_GROUP_N);
        t.releaseConstant(POOL_FIELD_P);
        return true;
    }

    /**
     * Emit the cheapest comb over the candidate window widths.
     *
     * <p>Each candidate is rendered in full and scored with the same byte-cost model the emitter is
     * measured by, and the smallest wins — the window width is not hardcoded. w=1 is the binary ladder
     * and is excluded; beyond w=4 the {@code 2^w} selection logic outgrows the saving.
     *
     * @return {@code null} when no candidate could be built, so the caller falls back to the ladder
     *     rather than emitting nothing
     */
    private static List<StackOp> emitCombBest(EcCodegenOptions opts) {
        List<StackOp> best = null;
        for (int w : new int[] {2, 3, 4}) {
            List<StackOp> ops = new ArrayList<>();
            if (!emitCombMulGen(ops::add, w, opts)) continue;
            if (best == null
                    || CostModel.estimateScriptBytes(ops) < CostModel.estimateScriptBytes(best)) {
                best = ops;
            }
        }
        return best;
    }

    public static void emitEcMulGen(Consumer<StackOp> emit) {
        emitEcMulGen(emit, null);
    }

    public static void emitEcMulGen(Consumer<StackOp> emit, EcCodegenOptions opts) {
        // G is a compile-time constant, so this is the one secp256k1 call site
        // where a fixed-base comb applies. emitEcMul cannot use it: its base
        // arrives at run time.
        if (opts != null && opts.fixedBaseComb()) {
            List<StackOp> ops = emitCombBest(opts);
            if (ops != null) {
                for (StackOp op : ops) emit.accept(op);
                return;
            }
        }

        byte[] gPoint = new byte[64];
        byte[] gx = bigintToBytes32(EC_GEN_X);
        byte[] gy = bigintToBytes32(EC_GEN_Y);
        System.arraycopy(gx, 0, gPoint, 0, 32);
        System.arraycopy(gy, 0, gPoint, 32, 32);
        emit.accept(new PushOp(PushValue.ofHex(hexOf(gPoint))));
        emit.accept(new SwapOp());
        emitEcMul(emit, opts);
    }

    public static void emitEcNegate(Consumer<StackOp> emit) {
        emitEcNegate(emit, null);
    }

    public static void emitEcNegate(Consumer<StackOp> emit, EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pt"), emit, opts, null);
        t.poolConstant(POOL_FIELD_P, EC_FIELD_P);
        decomposePoint(t, "_pt", "_nx", "_ny");
        pushFieldP(t, "_fp");
        fieldSub(t, "_fp", "_ny", "_neg_y");
        composePoint(t, "_nx", "_neg_y", "_result");
        t.releaseConstant(POOL_FIELD_P);
    }

    public static void emitEcOnCurve(Consumer<StackOp> emit) {
        emitEcOnCurve(emit, null);
    }

    public static void emitEcOnCurve(Consumer<StackOp> emit, EcCodegenOptions opts) {
        ECTracker t = new ECTracker(List.of("_pt"), emit, opts, null);
        t.poolConstant(POOL_FIELD_P, EC_FIELD_P);
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

        // on-curve = canonical AND curve-equation
        t.toTop("_canon");
        t.toTop("_curve_eq");
        t.rawBlock(List.of("_canon", "_curve_eq"), "_result",
            e -> e.accept(new OpcodeOp("OP_BOOLAND")));
        t.releaseConstant(POOL_FIELD_P);
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
        dispatch(funcName, emit, null);
    }

    public static void dispatch(String funcName, Consumer<StackOp> emit, EcCodegenOptions opts) {
        switch (funcName) {
            case "ecAdd" -> emitEcAdd(emit, opts);
            case "ecMul" -> emitEcMul(emit, opts);
            case "ecMulGen" -> emitEcMulGen(emit, opts);
            case "ecNegate" -> emitEcNegate(emit, opts);
            case "ecOnCurve" -> emitEcOnCurve(emit, opts);
            case "ecModReduce" -> emitEcModReduce(emit);
            case "ecEncodeCompressed" -> emitEcEncodeCompressed(emit);
            case "ecMakePoint" -> emitEcMakePoint(emit);
            case "ecPointX" -> emitEcPointX(emit);
            case "ecPointY" -> emitEcPointY(emit);
            default -> throw new RuntimeException("unknown EC builtin: " + funcName);
        }
    }
}
