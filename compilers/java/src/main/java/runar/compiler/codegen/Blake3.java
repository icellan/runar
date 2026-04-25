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
 * BLAKE3 compression codegen for Bitcoin Script.
 *
 * <p>Direct port of {@code compilers/go/codegen/blake3.go},
 * {@code compilers/rust/src/codegen/blake3.rs}, and
 * {@code compilers/python/runar_compiler/codegen/blake3.py}.
 *
 * <ul>
 *   <li>{@code emitBlake3Compress}: [chainingValue(32 BE), block(64 BE)] -&gt; [hash(32 BE)]</li>
 *   <li>{@code emitBlake3Hash}:     [message(&lt;=64 BE)] -&gt; [hash(32 BE)]</li>
 * </ul>
 *
 * <p>Architecture (same as {@link Sha256}):
 * <ul>
 *   <li>All 32-bit words stored as 4-byte little-endian during computation.</li>
 *   <li>LE additions via BIN2NUM/NUM2BIN (13 ops per add32).</li>
 *   <li>Byte-aligned rotations (16, 8) via SPLIT/SWAP/CAT on LE (4 ops).</li>
 *   <li>Non-byte-aligned rotations (12, 7) via LE-&gt;BE-&gt;rotrBE-&gt;BE-&gt;LE (31 ops).</li>
 *   <li>BE&lt;-&gt;LE conversion only at input unpack and output pack.</li>
 * </ul>
 *
 * <p>Stack layout during rounds:
 * <pre>
 *   [m0..m15, v0..v15]  (all LE 4-byte values)
 *   v15 at TOS (depth 0), v0 at depth 15, m15 at depth 16, m0 at depth 31.
 * </pre>
 */
public final class Blake3 {

    private Blake3() {}

    // ------------------------------------------------------------------
    // BLAKE3 constants
    // ------------------------------------------------------------------

    private static final long[] BLAKE3_IV = {
        0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL,
        0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L,
    };

    private static final int[] MSG_PERMUTATION = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
    };

    // Flags
    private static final int CHUNK_START = 1;
    private static final int CHUNK_END = 2;
    private static final int ROOT = 8;

    /** Encode uint32 as 4-byte little-endian. */
    private static byte[] u32ToLe(long n) {
        return new byte[]{
            (byte) (n & 0xff),
            (byte) ((n >> 8) & 0xff),
            (byte) ((n >> 16) & 0xff),
            (byte) ((n >> 24) & 0xff),
        };
    }

    /** Encode uint32 as 4-byte big-endian. */
    private static byte[] u32ToBe(long n) {
        return new byte[]{
            (byte) ((n >> 24) & 0xff),
            (byte) ((n >> 16) & 0xff),
            (byte) ((n >> 8) & 0xff),
            (byte) (n & 0xff),
        };
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Precompute message schedule for all 7 rounds
    // ------------------------------------------------------------------

    /**
     * For each round, compute which original message word index is used at
     * each position. Returns msgSchedule[round][position] = original msg word
     * index. This eliminates runtime message permutation -- we just pick from
     * the right depth at codegen time.
     */
    private static int[][] computeMsgSchedule() {
        int[][] schedule = new int[7][16];
        int[] current = new int[16];
        for (int i = 0; i < 16; i++) current[i] = i;
        for (int round = 0; round < 7; round++) {
            System.arraycopy(current, 0, schedule[round], 0, 16);
            int[] next = new int[16];
            for (int i = 0; i < 16; i++) {
                next[i] = current[MSG_PERMUTATION[i]];
            }
            current = next;
        }
        return schedule;
    }

    private static final int[][] MSG_SCHEDULE = computeMsgSchedule();

    // ==================================================================
    // State word position tracker
    // ==================================================================

    /**
     * Tracks the stack depth of each of the 16 state words. Depth 0 = TOS.
     * Message words sit below the state area at fixed positions.
     */
    private static final class StateTracker {
        final int[] positions = new int[16];

        StateTracker() {
            // Initial: v0 at depth 15 (deepest state word), v15 at depth 0 (TOS)
            for (int i = 0; i < 16; i++) {
                positions[i] = 15 - i;
            }
        }

        int depth(int wordIdx) {
            return positions[wordIdx];
        }

        /** Update tracker after rolling a state word from its depth to TOS. */
        void onRollToTop(int wordIdx) {
            int d = positions[wordIdx];
            for (int j = 0; j < 16; j++) {
                if (j != wordIdx && positions[j] >= 0 && positions[j] < d) {
                    positions[j]++;
                }
            }
            positions[wordIdx] = 0;
        }
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

        @SuppressWarnings("unused")
        void nip() {
            ops.add(new NipOp());
            depth--;
        }

        void rot() { ops.add(new RotOp()); }

        void pick(int d) {
            if (d == 0) { dup(); return; }
            if (d == 1) { over(); return; }
            pushI(d);
            ops.add(new PickOp(d));
        }

        void roll(int d) {
            if (d == 0) return;
            if (d == 1) { swap(); return; }
            if (d == 2) { rot(); return; }
            pushI(d);
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

        @SuppressWarnings("unused")
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
                    "BLAKE3 codegen: " + msg + ". Expected depth " + expected + ", got " + depth);
            }
        }

        // --- Byte reversal (only for BE<->LE conversion at boundaries) ---

        /** Reverse 4 bytes on TOS: [abcd] -&gt; [dcba]. Net: 0. 12 ops. */
        void reverseBytes4() {
            pushI(1); split();
            pushI(1); split();
            pushI(1); split();
            swap(); binOp("OP_CAT");
            swap(); binOp("OP_CAT");
            swap(); binOp("OP_CAT");
        }

        // --- LE <-> Numeric conversions (cheap -- no byte reversal) ---

        /** Convert 4-byte LE to unsigned script number. [le4] -&gt; [num]. Net: 0. 3 ops. */
        void le2num() {
            pushB(new byte[]{0x00});  // unsigned padding
            binOp("OP_CAT");
            uniOp("OP_BIN2NUM");
        }

        /** Convert script number to 4-byte LE (truncates to 32 bits). [num] -&gt; [le4]. Net: 0. 5 ops. */
        void num2le() {
            pushI(5);
            binOp("OP_NUM2BIN"); // 5-byte LE
            pushI(4);
            split();             // [4-byte LE, overflow+sign]
            drop();              // discard overflow byte
        }

        // --- LE arithmetic ---

        /** [a(LE), b(LE)] -&gt; [(a+b mod 2^32)(LE)]. Net: -1. 13 ops. */
        void add32() {
            le2num();
            swap();
            le2num();
            binOp("OP_ADD");
            num2le();
        }

        /** Add N LE values. [v0..vN-1] (vN-1=TOS) -&gt; [sum(LE)]. Net: -(N-1). */
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

        // --- ROTR/SHR using OP_LSHIFT/OP_RSHIFT ---

        /** ROTR(x, n) on BE 4-byte value. [x_BE] -&gt; [rotated_BE]. Net: 0. 7 ops. */
        void rotrBe(int n) {
            dup();
            pushI(n);
            binOp("OP_RSHIFT");
            swap();
            pushI(32 - n);
            binOp("OP_LSHIFT");
            binOp("OP_OR");
        }

        // --- ROTR on LE values ---

        /** ROTR(x, 16) on LE 4-byte value. Swaps the two 16-bit halves. Net: 0. 4 ops. */
        void rotr16Le() {
            pushI(2);
            split();         // [lo2, hi2]
            swap();          // [hi2, lo2]
            binOp("OP_CAT"); // [hi2||lo2]
        }

        /** ROTR(x, 8) on LE 4-byte value. [b0,b1,b2,b3] -&gt; [b1,b2,b3,b0]. Net: 0. 4 ops. */
        void rotr8Le() {
            pushI(1);
            split();         // [b0, b1b2b3]
            swap();          // [b1b2b3, b0]
            binOp("OP_CAT"); // [b1b2b3||b0]
        }

        /**
         * ROTR(x, n) on LE 4-byte value (general, non-byte-aligned). Net: 0. 31 ops.
         * Converts LE-&gt;BE, applies rotrBe, converts back.
         */
        void rotrLeGeneral(int n) {
            reverseBytes4(); // LE -> BE (12 ops)
            rotrBe(n);       // rotate on BE (7 ops)
            reverseBytes4(); // BE -> LE (12 ops)
        }

        /** Convert N x BE words on TOS to LE, preserving stack order. */
        void beWordsToLe(int n) {
            for (int i = 0; i < n; i++) {
                reverseBytes4();
                toAlt();
            }
            for (int i = 0; i < n; i++) {
                fromAlt();
            }
        }
    }

    // ==================================================================
    // G function (quarter-round)
    // ==================================================================

    /**
     * Emit one half of the G function.
     *
     * <p>Stack entry: [a, b, c, d, m] (m on TOS) -- 5 items.
     * Stack exit:  [a', b', c', d'] (d' on TOS) -- 4 items.
     * Net depth: -1.
     *
     * <p>Operations:
     * <pre>
     *   a' = a + b + m
     *   d' = (d ^ a') &gt;&gt;&gt; rotD
     *   c' = c + d'
     *   b' = (original_b ^ c') &gt;&gt;&gt; rotB
     * </pre>
     */
    private static void emitHalfG(Emitter em, int rotD, int rotB) {
        int d0 = em.depth;

        // Save original b for step 4 (b is at depth 3)
        em.pick(3);
        em.toAlt();

        // Step 1: a' = a + b + m
        // Stack: [a, b, c, d, m] -- a=4, b=3, c=2, d=1, m=0
        em.roll(3);   // [a, c, d, m, b]
        em.roll(4);   // [c, d, m, b, a]
        em.addN(3);   // [c, d, a']
        em.assertDepth(d0 - 2, "halfG step1");

        // Step 2: d' = (d ^ a') >>> rotD
        // Stack: [c, d, a'] -- c=2, d=1, a'=0
        em.dup();           // [c, d, a', a']
        em.rot();           // [c, a', a', d]
        em.binOp("OP_XOR"); // [c, a', (d^a')]
        if (rotD == 16) {
            em.rotr16Le();
        } else if (rotD == 8) {
            em.rotr8Le();
        } else {
            em.rotrLeGeneral(rotD);
        }
        em.assertDepth(d0 - 2, "halfG step2");

        // Step 3: c' = c + d'
        // Stack: [c, a', d']
        em.dup();   // [c, a', d', d']
        em.roll(3); // [a', d', d', c]
        em.add32(); // [a', d', c']
        em.assertDepth(d0 - 2, "halfG step3");

        // Step 4: b' = (original_b ^ c') >>> rotB
        // Stack: [a', d', c']
        em.fromAlt();       // [a', d', c', b]
        em.over();          // [a', d', c', b, c']
        em.binOp("OP_XOR"); // [a', d', c', (b^c')]
        em.rotrLeGeneral(rotB);
        // Stack: [a', d', c', b']
        em.assertDepth(d0 - 1, "halfG step4");

        // Rearrange: [a', d', c', b'] -> [a', b', c', d']
        em.swap(); // [a', d', b', c']
        em.rot();  // [a', b', c', d']
        em.assertDepth(d0 - 1, "halfG done");
    }

    /**
     * Emit the full G function (quarter-round).
     *
     * <p>Stack entry: [a, b, c, d, mx, my] (my on TOS) -- 6 items.
     * Stack exit:  [a', b', c', d'] (d' on TOS) -- 4 items.
     * Net depth: -2.
     */
    private static void emitG(Emitter em) {
        int d0 = em.depth;

        // Save my to alt for phase 2
        em.toAlt(); // [a, b, c, d, mx]

        // Phase 1: first half with mx, ROTR(16) and ROTR(12)
        emitHalfG(em, 16, 12);
        em.assertDepth(d0 - 2, "G phase1");

        // Restore my for phase 2
        em.fromAlt(); // [a', b', c', d', my]
        em.assertDepth(d0 - 1, "G before phase2");

        // Phase 2: second half with my, ROTR(8) and ROTR(7)
        emitHalfG(em, 8, 7);
        em.assertDepth(d0 - 2, "G done");
    }

    // ==================================================================
    // G call with state management
    // ==================================================================

    /**
     * Emit a single G call with state word roll management.
     * Rolls 4 state words (ai, bi, ci, di) to top, picks 2 message words,
     * runs G, then updates tracker.
     */
    private static void emitGCall(
        Emitter em,
        StateTracker tracker,
        int ai, int bi, int ci, int di,
        int mxOrigIdx, int myOrigIdx
    ) {
        int d0 = em.depth;

        // Roll 4 state words to top: a, b, c, d (d ends up as TOS)
        int[] order = {ai, bi, ci, di};
        for (int idx : order) {
            em.roll(tracker.depth(idx));
            tracker.onRollToTop(idx);
        }

        // Pick message words from below the 16 state word area
        // m[i] is at depth: 16 (state words) + (15 - i)
        em.pick(16 + (15 - mxOrigIdx));
        em.pick(16 + (15 - myOrigIdx) + 1); // +1 for mx just pushed
        em.assertDepth(d0 + 2, "before G");

        // Run G: consumes 6 (a, b, c, d, mx, my), produces 4 (a', b', c', d')
        emitG(em);
        em.assertDepth(d0, "after G");

        // Update tracker: result words at depths 0-3
        tracker.positions[ai] = 3;
        tracker.positions[bi] = 2;
        tracker.positions[ci] = 1;
        tracker.positions[di] = 0;
    }

    // ==================================================================
    // Full compression ops generator
    // ==================================================================

    /**
     * Generate BLAKE3 compression ops.
     *
     * <p>Stack entry: [..., chainingValue(32 BE), block(64 BE)] -- 2 items.
     * Stack exit:  [..., hash(32 BE)] -- 1 item.
     * Net depth: -1.
     */
    private static List<StackOp> generateCompressOps() {
        Emitter em = new Emitter(2);

        // ================================================================
        // Phase 1: Unpack block into 16 LE message words
        // ================================================================
        // Stack: [chainingValue(32 BE), block(64 BE)]
        // Split block into 16 x 4-byte BE words, convert to LE
        for (int i = 0; i < 15; i++) em.split4();
        em.assertDepth(17, "after block unpack"); // 16 block words + 1 chainingValue
        em.beWordsToLe(16);
        em.assertDepth(17, "after block LE convert");
        // Stack: [CV, m0(LE), m1(LE), ..., m15(LE)] -- m0 deepest of msg words, m15 TOS

        // ================================================================
        // Phase 2: Initialize 16-word state on top of message words
        // ================================================================
        // Move CV to alt (it's below the 16 msg words, at depth 16)
        em.roll(16);
        em.toAlt();
        em.assertDepth(16, "after CV to alt");
        // Stack: [m0, m1, ..., m15]  Alt: [CV]

        // Get CV back, split into 8 LE words, place on top of msg
        em.fromAlt();
        em.assertDepth(17, "after CV from alt");
        for (int i = 0; i < 7; i++) em.split4();
        em.assertDepth(24, "after cv unpack");
        em.beWordsToLe(8);
        em.assertDepth(24, "after cv LE convert");
        // Stack: [m0..m15, cv0(LE)..cv7(LE)]

        // v[0..7] = chaining value (already on stack)
        // v[8..11] = IV[0..3]
        for (int i = 0; i < 4; i++) {
            em.pushB(u32ToLe(BLAKE3_IV[i]));
        }
        em.assertDepth(28, "after IV push");

        // v[12] = counter_low = 0, v[13] = counter_high = 0
        em.pushB(u32ToLe(0));
        em.pushB(u32ToLe(0));
        // v[14] = block_len = 64
        em.pushB(u32ToLe(64));
        // v[15] = flags = CHUNK_START | CHUNK_END | ROOT = 11
        em.pushB(u32ToLe(CHUNK_START | CHUNK_END | ROOT));
        em.assertDepth(32, "after state init");

        // Stack: [m0..m15(bottom), v0..v15(top)] -- v15=TOS, m0=deepest

        // ================================================================
        // Phase 3: 7 rounds of G function calls
        // ================================================================
        StateTracker tracker = new StateTracker();

        for (int round = 0; round < 7; round++) {
            int[] s = MSG_SCHEDULE[round];

            // Column mixing
            emitGCall(em, tracker, 0, 4, 8, 12, s[0], s[1]);
            emitGCall(em, tracker, 1, 5, 9, 13, s[2], s[3]);
            emitGCall(em, tracker, 2, 6, 10, 14, s[4], s[5]);
            emitGCall(em, tracker, 3, 7, 11, 15, s[6], s[7]);

            // Diagonal mixing
            emitGCall(em, tracker, 0, 5, 10, 15, s[8], s[9]);
            emitGCall(em, tracker, 1, 6, 11, 12, s[10], s[11]);
            emitGCall(em, tracker, 2, 7, 8, 13, s[12], s[13]);
            emitGCall(em, tracker, 3, 4, 9, 14, s[14], s[15]);
        }

        em.assertDepth(32, "after all rounds");

        // ================================================================
        // Phase 4: Output -- hash[i] = state[i] XOR state[i+8], for i=0..7
        // ================================================================

        // Reorder state words to canonical positions using alt stack
        for (int i = 15; i >= 0; i--) {
            int d = tracker.depth(i);
            em.roll(d);
            tracker.onRollToTop(i);
            em.toAlt();
            // Remaining words shift up because one was removed from main
            for (int j = 0; j < 16; j++) {
                if (j != i && tracker.positions[j] >= 0) {
                    tracker.positions[j]--;
                }
            }
            tracker.positions[i] = -1;
        }

        // Pop to get canonical order: [v0(bottom)..v15(TOS)]
        for (int i = 0; i < 16; i++) {
            em.fromAlt();
        }
        em.assertDepth(32, "after canonical reorder");

        // State: [m0..m15, v0(bottom)..v15(TOS)], canonical order.
        // XOR pairs: h[7-k] = v[7-k] ^ v[15-k] for k=0..7
        // Process top-down: v15^v7, v14^v6, ..., v8^v0. Send each result to alt.
        for (int k = 0; k < 8; k++) {
            em.roll(8 - k);     // bring v[7-k] to TOS (past v[15-k] and remaining)
            em.binOp("OP_XOR"); // h[7-k] = v[7-k] ^ v[15-k]
            em.toAlt();         // result to alt; main shrinks by 2
        }
        em.assertDepth(16, "after XOR pairs");
        // Alt (bottom->top): h7, h6, h5, h4, h3, h2, h1, h0. Main: [m0..m15].

        // Pop results to main: h0 first (LIFO), then h1, ..., h7
        for (int i = 0; i < 8; i++) {
            em.fromAlt();
        }
        em.assertDepth(24, "after XOR results restored");
        // Main: [m0..m15, h0, h1, ..., h7] h7=TOS

        // Pack into 32-byte BE result: h0_BE || h1_BE || ... || h7_BE
        em.reverseBytes4(); // h7 -> h7_BE
        for (int i = 1; i < 8; i++) {
            em.swap();          // bring h[7-i] (LE) to TOS
            em.reverseBytes4(); // -> BE
            em.swap();          // [new_BE, accumulated]
            em.binOp("OP_CAT"); // new_BE || accumulated
        }
        em.assertDepth(17, "after hash pack");

        // Drop 16 message words
        for (int i = 0; i < 16; i++) {
            em.swap();
            em.drop();
        }
        em.assertDepth(1, "compress final");

        return em.ops;
    }

    // Cache the compression ops (identical every call)
    private static volatile List<StackOp> compressOpsCache = null;

    private static List<StackOp> getCompressOps() {
        List<StackOp> local = compressOpsCache;
        if (local == null) {
            synchronized (Blake3.class) {
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
     * Emit BLAKE3 single-block compression in Bitcoin Script.
     * Stack on entry: [..., chainingValue(32 BE), block(64 BE)]
     * Stack on exit:  [..., hash(32 BE)]
     * Net depth: -1.
     */
    public static void emitBlake3Compress(Consumer<StackOp> emit) {
        for (StackOp op : getCompressOps()) emit.accept(op);
    }

    /**
     * Emit BLAKE3 hash for a message up to 64 bytes.
     * Stack on entry: [..., message(&lt;=64 BE)]
     * Stack on exit:  [..., hash(32 BE)]
     * Net depth: 0.
     *
     * <p>Applies zero-padding and uses IV as chaining value.
     */
    public static void emitBlake3Hash(Consumer<StackOp> emit) {
        Emitter em = new Emitter(1);

        // Pad message to 64 bytes (BLAKE3 zero-pads, no length suffix)
        em.oc("OP_SIZE"); em.depth += 1; // [message, len]
        em.pushI(64);
        em.swap();
        em.binOp("OP_SUB");    // [message, 64-len]
        em.pushI(0);
        em.swap();
        em.binOp("OP_NUM2BIN"); // [message, zeros]
        em.binOp("OP_CAT");    // [paddedMessage(64)]

        // Push IV as 32-byte BE chaining value
        byte[] ivBytes = new byte[32];
        for (int i = 0; i < 8; i++) {
            byte[] be = u32ToBe(BLAKE3_IV[i]);
            ivBytes[i * 4]     = be[0];
            ivBytes[i * 4 + 1] = be[1];
            ivBytes[i * 4 + 2] = be[2];
            ivBytes[i * 4 + 3] = be[3];
        }
        em.pushB(ivBytes);
        em.swap(); // [IV(32 BE), paddedMessage(64 BE)]

        // Splice compression ops
        List<StackOp> compressOps = getCompressOps();
        for (StackOp op : compressOps) em.eRaw(op);
        em.depth = 1;

        em.assertDepth(1, "blake3Hash final");
        for (StackOp op : em.ops) emit.accept(op);
    }

    // ==================================================================
    // Dispatch
    // ==================================================================

    private static final java.util.Set<String> NAMES = java.util.Set.of(
        "blake3Compress", "blake3Hash"
    );

    public static boolean isBlake3Builtin(String name) {
        return NAMES.contains(name);
    }

    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        switch (funcName) {
            case "blake3Compress" -> emitBlake3Compress(emit);
            case "blake3Hash" -> emitBlake3Hash(emit);
            default -> throw new RuntimeException("unknown BLAKE3 builtin: " + funcName);
        }
    }
}
