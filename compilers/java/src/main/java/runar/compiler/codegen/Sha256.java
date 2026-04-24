package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
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
 * SHA-256 compression codegen for Bitcoin Script.
 *
 * <p>Direct port of {@code compilers/python/runar_compiler/codegen/sha256.py}
 * and {@code packages/runar-compiler/src/passes/sha256-codegen.ts}.
 *
 * <ul>
 *   <li>{@code emitSha256Compress}: [state(32), block(64)] -&gt; [newState(32)]</li>
 *   <li>{@code emitSha256Finalize}: [state(32), remaining(var), msgBitLen] -&gt; [hash(32)]</li>
 * </ul>
 *
 * <p>32-bit words are stored as 4-byte little-endian during computation.
 * LE&lt;-&gt;num conversion is push(0x00)+CAT+BIN2NUM (3 ops). Bitwise ops
 * are endian-agnostic on equal-length arrays. ROTR uses OP_LSHIFT/OP_RSHIFT
 * on BE byte arrays. BE-&gt;LE conversion only at input unpack; LE-&gt;BE only at
 * output pack.
 */
public final class Sha256 {

    private Sha256() {}

    // ------------------------------------------------------------------
    // SHA-256 round constants
    // ------------------------------------------------------------------

    private static final long[] K = {
        0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
        0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
        0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L,
        0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
        0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL,
        0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
        0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L,
        0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
        0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L,
        0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
        0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L,
        0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
        0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L,
        0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
        0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L,
        0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L,
    };

    /** Encode uint32 as 4-byte little-endian. */
    private static byte[] u32ToLe(long n) {
        return new byte[]{
            (byte) (n & 0xff),
            (byte) ((n >> 8) & 0xff),
            (byte) ((n >> 16) & 0xff),
            (byte) ((n >> 24) & 0xff),
        };
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    // ==================================================================
    // Emitter with depth tracking
    // ==================================================================

    private static final class Emitter {
        final List<StackOp> ops = new ArrayList<>();
        int depth;
        int altDepth = 0;

        Emitter(int initialDepth) {
            this.depth = initialDepth;
        }

        void eRaw(StackOp s) { ops.add(s); }

        void oc(String code) {
            ops.add(new OpcodeOp(code));
        }

        void pushI(long v) {
            ops.add(new PushOp(PushValue.of(BigInteger.valueOf(v))));
            depth++;
        }

        void pushB(byte[] v) {
            ops.add(new PushOp(PushValue.ofHex(hex(v))));
            depth++;
        }

        void dup() {
            ops.add(new DupOp());
            depth++;
        }

        void drop() {
            ops.add(new DropOp());
            depth--;
        }

        void swap() { ops.add(new SwapOp()); }

        void over() {
            ops.add(new OverOp());
            depth++;
        }

        void nip() {
            ops.add(new NipOp());
            depth--;
        }

        void rot() { ops.add(new RotOp()); }

        void pick(int d) {
            if (d == 0) { dup(); return; }
            if (d == 1) { over(); return; }
            pushI(d);
            // PickOp leaves the stack effectively at depth+1 vs entry (the N
            // push is consumed but a copy of the element is added).
            ops.add(new PickOp(d));
        }

        void roll(int d) {
            if (d == 0) return;
            if (d == 1) { swap(); return; }
            if (d == 2) { rot(); return; }
            pushI(d);
            // ROLL consumes N and removes-then-pushes element at depth d -> net 0
            ops.add(new RollOp(d));
            depth--;
        }

        void toAlt() {
            oc("OP_TOALTSTACK");
            depth--;
            altDepth++;
        }

        void fromAlt() {
            oc("OP_FROMALTSTACK");
            depth++;
            altDepth--;
        }

        void binOp(String code) {
            oc(code);
            depth--;
        }

        void uniOp(String code) {
            oc(code);
        }

        void dup2() {
            oc("OP_2DUP");
            depth += 2;
        }

        void split() { oc("OP_SPLIT"); }

        void split4() {
            pushI(4);
            split();
        }

        void assertDepth(int expected, String msg) {
            if (depth != expected) {
                throw new RuntimeException(
                    "SHA256 codegen: " + msg + ". Expected depth " + expected + ", got " + depth);
            }
        }

        // --- Byte reversal (only for BE<->LE conversion at boundaries) ---

        void reverseBytes4() {
            // [abcd] -> [dcba]. Net 0. 12 ops.
            pushI(1); split();
            pushI(1); split();
            pushI(1); split();
            swap(); binOp("OP_CAT");
            swap(); binOp("OP_CAT");
            swap(); binOp("OP_CAT");
        }

        // --- LE <-> Numeric conversions ---

        void le2num() {
            pushB(new byte[]{0x00});
            binOp("OP_CAT");
            uniOp("OP_BIN2NUM");
        }

        void num2le() {
            pushI(5);
            binOp("OP_NUM2BIN"); // 5-byte LE
            pushI(4);
            split();             // [4-byte LE, overflow+sign]
            drop();              // discard overflow byte
        }

        // --- LE arithmetic ---

        void add32() {
            le2num();
            swap();
            le2num();
            binOp("OP_ADD");
            num2le();
        }

        void addN(int n) {
            if (n < 2) return;
            le2num();
            for (int i = 1; i < n; i++) {
                swap();
                le2num();
                binOp("OP_ADD");
            }
            num2le();
        }

        // --- ROTR/SHR using OP_LSHIFT/OP_RSHIFT on BE byte arrays ---

        void rotrBe(int n) {
            dup();
            pushI(n);
            binOp("OP_RSHIFT");
            swap();
            pushI(32 - n);
            binOp("OP_LSHIFT");
            binOp("OP_OR");
        }

        void shrBe(int n) {
            pushI(n);
            binOp("OP_RSHIFT");
        }

        // --- SHA-256 sigma functions ---

        void bigSigma0() {
            reverseBytes4();
            dup(); dup();
            rotrBe(2); swap(); rotrBe(13);
            binOp("OP_XOR");
            swap(); rotrBe(22);
            binOp("OP_XOR");
            reverseBytes4();
        }

        void bigSigma1() {
            reverseBytes4();
            dup(); dup();
            rotrBe(6); swap(); rotrBe(11);
            binOp("OP_XOR");
            swap(); rotrBe(25);
            binOp("OP_XOR");
            reverseBytes4();
        }

        void smallSigma0() {
            reverseBytes4();
            dup(); dup();
            rotrBe(7); swap(); rotrBe(18);
            binOp("OP_XOR");
            swap(); shrBe(3);
            binOp("OP_XOR");
            reverseBytes4();
        }

        void smallSigma1() {
            reverseBytes4();
            dup(); dup();
            rotrBe(17); swap(); rotrBe(19);
            binOp("OP_XOR");
            swap(); shrBe(10);
            binOp("OP_XOR");
            reverseBytes4();
        }

        void ch() {
            rot();
            dup();
            uniOp("OP_INVERT");
            rot();
            binOp("OP_AND");
            toAlt();
            binOp("OP_AND");
            fromAlt();
            binOp("OP_XOR");
        }

        void maj() {
            toAlt();
            dup2();
            binOp("OP_AND");
            toAlt();
            binOp("OP_XOR");
            fromAlt();
            swap();
            fromAlt();
            binOp("OP_AND");
            binOp("OP_OR");
        }

        void beWordsToLe(int n) {
            for (int i = 0; i < n; i++) {
                reverseBytes4();
                toAlt();
            }
            for (int i = 0; i < n; i++) {
                fromAlt();
            }
        }

        void beWordsToLeReversed8() {
            // Pre: [a(deep)..h(TOS)] BE.  Post: [h(deep)..a(TOS)] LE.
            for (int i = 7; i >= 0; i--) {
                roll(i);
                reverseBytes4();
                toAlt();
            }
            for (int i = 0; i < 8; i++) {
                fromAlt();
            }
        }
    }

    // ==================================================================
    // Compression rounds generator
    // ==================================================================

    private static void emitRound(Emitter em, int t) {
        // T1 = S1(e) + Ch(e,f,g) + h + K[t] + W[t]
        em.pick(4);
        em.bigSigma1();

        em.pick(5); em.pick(7); em.pick(9);
        em.ch();

        em.pick(9);
        em.pushB(u32ToLe(K[t]));
        em.pick(75 - t);

        em.addN(5);

        // T2 = S0(a) + Maj(a,b,c)
        em.dup(); em.toAlt();

        em.pick(1);
        em.bigSigma0();

        em.pick(2); em.pick(4); em.pick(6);
        em.maj();
        em.add32();

        // Register update
        em.fromAlt();

        em.swap();
        em.add32();

        em.swap();
        em.roll(5);
        em.add32();

        em.roll(8); em.drop();

        em.swap(); em.roll(4); em.roll(4); em.roll(4); em.roll(3);
    }

    private static List<StackOp> generateCompressOps() {
        Emitter em = new Emitter(2);

        // Phase 1: Save init state, unpack block into 16 LE words
        em.swap();
        em.dup(); em.toAlt();
        em.toAlt();
        em.assertDepth(1, "compress: after state save");

        for (int i = 0; i < 15; i++) em.split4();
        em.assertDepth(16, "compress: after block unpack");
        em.beWordsToLe(16);
        em.assertDepth(16, "compress: after block LE convert");

        // Phase 2: W expansion
        for (int t = 16; t < 64; t++) {
            em.over(); em.smallSigma1();
            em.pick(6 + 1);
            em.pick(14 + 2); em.smallSigma0();
            em.pick(15 + 3);
            em.addN(4);
        }
        em.assertDepth(64, "compress: after W expansion");

        // Phase 3: Unpack state
        em.fromAlt();
        for (int i = 0; i < 7; i++) em.split4();
        em.assertDepth(72, "compress: after state unpack");
        em.beWordsToLeReversed8();
        em.assertDepth(72, "compress: after state LE convert");

        // Phase 4: 64 compression rounds
        for (int t = 0; t < 64; t++) {
            int d0 = em.depth;
            emitRound(em, t);
            em.assertDepth(d0, "compress: after round " + t);
        }

        // Phase 5: Add initial state, pack result
        em.fromAlt();
        em.assertDepth(73, "compress: before final add");

        for (int i = 0; i < 7; i++) em.split4();
        em.beWordsToLeReversed8();
        em.assertDepth(80, "compress: after init unpack");

        for (int i = 0; i < 8; i++) {
            em.roll(8 - i);
            em.add32();
            em.toAlt();
        }
        em.assertDepth(64, "compress: after final add");

        em.fromAlt();
        em.reverseBytes4();
        for (int i = 1; i < 8; i++) {
            em.fromAlt();
            em.reverseBytes4();
            em.swap();
            em.binOp("OP_CAT");
        }
        em.assertDepth(65, "compress: after pack");

        for (int i = 0; i < 64; i++) {
            em.swap(); em.drop();
        }
        em.assertDepth(1, "compress: final");

        return em.ops;
    }

    // Cache the compression ops
    private static volatile List<StackOp> compressOpsCache = null;

    private static List<StackOp> getCompressOps() {
        List<StackOp> local = compressOpsCache;
        if (local == null) {
            synchronized (Sha256.class) {
                local = compressOpsCache;
                if (local == null) {
                    local = List.copyOf(generateCompressOps());
                    compressOpsCache = local;
                }
            }
        }
        return local;
    }

    // ==================================================================
    // Public entry points
    // ==================================================================

    /**
     * Emit SHA-256 compression.
     * Stack on entry: [..., state(32 BE), block(64 BE)]
     * Stack on exit:  [..., newState(32 BE)]
     */
    public static void emitSha256Compress(Consumer<StackOp> emit) {
        for (StackOp op : getCompressOps()) emit.accept(op);
    }

    /**
     * Emit SHA-256 finalization with padding.
     * Stack on entry: [..., state(32 BE), remaining(var BE), msgBitLen(bigint)]
     * Stack on exit:  [..., hash(32 BE)]
     */
    public static void emitSha256Finalize(Consumer<StackOp> emit) {
        Emitter em = new Emitter(3);

        // ---- Step 1: Convert msgBitLen to 8-byte BE ----
        em.pushI(9);
        em.binOp("OP_NUM2BIN");
        em.pushI(8);
        em.split();
        em.drop();
        em.pushI(4); em.split();
        em.reverseBytes4();
        em.swap();
        em.reverseBytes4();
        em.binOp("OP_CAT");
        em.toAlt();
        em.assertDepth(2, "finalize: after bitLen conversion");

        // ---- Step 2: Pad remaining ----
        em.pushB(new byte[]{(byte) 0x80});
        em.binOp("OP_CAT");

        em.oc("OP_SIZE");
        em.depth += 1;

        em.dup();
        em.pushI(57);
        em.binOp("OP_LESSTHAN");

        em.oc("OP_IF");
        em.depth -= 1;
        // ---- 1-block path: pad to 56 bytes ----
        em.pushI(56);
        em.swap();
        em.binOp("OP_SUB");
        em.pushI(0);
        em.swap();
        em.binOp("OP_NUM2BIN");
        em.binOp("OP_CAT");
        em.fromAlt();
        em.binOp("OP_CAT");
        List<StackOp> compressOps = getCompressOps();
        for (StackOp op : compressOps) em.eRaw(op);
        em.depth = 1;

        em.oc("OP_ELSE");
        em.depth = 3;

        // ---- 2-block path: pad to 120 bytes ----
        em.pushI(120);
        em.swap();
        em.binOp("OP_SUB");
        em.pushI(0);
        em.swap();
        em.binOp("OP_NUM2BIN");
        em.binOp("OP_CAT");
        em.fromAlt();
        em.binOp("OP_CAT");

        em.pushI(64);
        em.split();
        em.toAlt();

        for (StackOp op : compressOps) em.eRaw(op);
        em.depth = 1;

        em.fromAlt();
        for (StackOp op : compressOps) em.eRaw(op);
        em.depth = 1;

        em.oc("OP_ENDIF");
        em.assertDepth(1, "finalize: final");

        for (StackOp op : em.ops) emit.accept(op);
    }
}
