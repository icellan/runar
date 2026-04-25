package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * SLH-DSA (FIPS 205) Bitcoin Script codegen for the Rúnar Java stack lowerer.
 *
 * <p>Direct port of {@code compilers/python/runar_compiler/codegen/slh_dsa.py}
 * (and the canonical {@code compilers/rust/src/codegen/slh_dsa.rs}). All six
 * helpers in this file produce byte-identical {@link StackOp} streams to those
 * reference implementations for the same input parameter set.
 *
 * <p>Entry: {@link #emitVerifySlhDsa(Consumer, String)} emits the full
 * verification script. Six FIPS 205 SHA2 parameter sets are supported:
 * {@code SHA2_128s}, {@code SHA2_128f}, {@code SHA2_192s}, {@code SHA2_192f},
 * {@code SHA2_256s}, {@code SHA2_256f}. Resulting scripts range from ~200 KB
 * (128s) to ~900 KB (256f).
 *
 * <p>Main-stack convention: {@code pkSeedPad} (64 bytes) tracked as
 * {@code _pkSeedPad} on the main stack, accessed via PICK at known depth.
 * Never placed on alt.
 *
 * <p>Runtime ADRS: {@code treeAddr} (8-byte BE) and {@code keypair} (4-byte
 * BE) are tracked on the main stack as {@code treeAddr8} and {@code keypair4},
 * threaded into raw blocks. ADRS is built at runtime using
 * {@code emitBuildAdrs}/{@code emitBuildAdrs18} helpers.
 */
public final class SlhDsa {

    private SlhDsa() {}

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /** Set of builtin names that route to {@link #emitVerifySlhDsa}. */
    private static final Set<String> NAMES = Set.of(
        "verifySLHDSA_SHA2_128s",
        "verifySLHDSA_SHA2_128f",
        "verifySLHDSA_SHA2_192s",
        "verifySLHDSA_SHA2_192f",
        "verifySLHDSA_SHA2_256s",
        "verifySLHDSA_SHA2_256f"
    );

    public static boolean isSlhDsaBuiltin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Extract the parameter-set key (e.g. {@code "SHA2_128s"}) from a builtin
     * name like {@code "verifySLHDSA_SHA2_128s"}.
     */
    public static String paramKey(String builtinName) {
        if (!builtinName.startsWith("verifySLHDSA_")) {
            throw new IllegalArgumentException("not an SLH-DSA builtin: " + builtinName);
        }
        return builtinName.substring("verifySLHDSA_".length());
    }

    /**
     * Emit the full SLH-DSA verification script.
     *
     * <p>Stack on entry: {@code [..., msg, sig, pubkey]} (pubkey on top).
     * Stack on exit: {@code [..., bool]} where 1 = signature valid, 0 = invalid.
     */
    public static void emitVerifySlhDsa(Consumer<StackOp> emit, String paramKey) {
        SLHCodegenParams p = SLH_PARAMS.get(paramKey);
        if (p == null) {
            throw new RuntimeException("Unknown SLH-DSA params: " + paramKey);
        }
        emitVerifySlhDsaInternal(emit, p);
    }

    // ------------------------------------------------------------------
    // 1. Parameter sets (FIPS 205 Table 1, SHA2)
    // ------------------------------------------------------------------

    private static final class SLHCodegenParams {
        final int n;     // hash bytes (16/24/32)
        final int h;     // total tree height
        final int d;     // hypertree layers
        final int hp;    // subtree height (h/d)
        final int a;     // FORS tree height
        final int k;     // FORS tree count
        final int w;     // Winternitz parameter (16)
        final int len;   // WOTS+ chain count
        final int len1;  // message chains (2*n)
        final int len2;  // checksum chains (3 for all SHA2 sets)

        SLHCodegenParams(int n, int h, int d, int hp, int a, int k,
                         int w, int len, int len1, int len2) {
            this.n = n;
            this.h = h;
            this.d = d;
            this.hp = hp;
            this.a = a;
            this.k = k;
            this.w = w;
            this.len = len;
            this.len1 = len1;
            this.len2 = len2;
        }
    }

    private static SLHCodegenParams slhMk(int n, int h, int d, int a, int k) {
        int len1 = 2 * n;
        // floor(log2(len1*15) / log2(16)) + 1
        int len2 = (int) Math.floor(Math.log(len1 * 15.0) / Math.log(16.0)) + 1;
        return new SLHCodegenParams(n, h, d, h / d, a, k, 16, len1 + len2, len1, len2);
    }

    private static final Map<String, SLHCodegenParams> SLH_PARAMS = Map.of(
        "SHA2_128s", slhMk(16, 63, 7, 12, 14),
        "SHA2_128f", slhMk(16, 66, 22, 6, 33),
        "SHA2_192s", slhMk(24, 63, 7, 14, 17),
        "SHA2_192f", slhMk(24, 66, 22, 8, 33),
        "SHA2_256s", slhMk(32, 64, 8, 14, 22),
        "SHA2_256f", slhMk(32, 68, 17, 8, 35)
    );

    // ADRS type constants
    private static final int SLH_WOTS_HASH = 0;
    private static final int SLH_WOTS_PK = 1;
    private static final int SLH_TREE = 2;
    private static final int SLH_FORS_TREE = 3;
    private static final int SLH_FORS_ROOTS = 4;

    // ------------------------------------------------------------------
    // 2. Misc helpers
    // ------------------------------------------------------------------

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private static PushOp pushBytes(byte[] v) {
        return new PushOp(PushValue.ofHex(hex(v)));
    }

    private static PushOp pushInt(long n) {
        return new PushOp(PushValue.of(BigInteger.valueOf(n)));
    }

    private static PushOp pushBigInt(BigInteger n) {
        return new PushOp(PushValue.of(n));
    }

    /** Emit unrolled fixed-length byte reversal for {@code n} bytes. */
    private static List<StackOp> emitReverseN(int n) {
        if (n <= 1) return List.of();
        List<StackOp> ops = new ArrayList<>(4 * (n - 1));
        for (int i = 0; i < n - 1; i++) {
            ops.add(pushInt(1));
            ops.add(new OpcodeOp("OP_SPLIT"));
        }
        for (int i = 0; i < n - 1; i++) {
            ops.add(new SwapOp());
            ops.add(new OpcodeOp("OP_CAT"));
        }
        return ops;
    }

    /** Compile-time integer to 4-byte big-endian. */
    private static byte[] int4be(int v) {
        return new byte[]{
            (byte) ((v >> 24) & 0xff),
            (byte) ((v >> 16) & 0xff),
            (byte) ((v >> 8) & 0xff),
            (byte) (v & 0xff),
        };
    }

    /** Collect ops emitted by the supplied callback into a list. */
    private static List<StackOp> collectOps(Consumer<Consumer<StackOp>> fn) {
        List<StackOp> ops = new ArrayList<>();
        fn.accept(ops::add);
        return ops;
    }

    // ------------------------------------------------------------------
    // 3. Runtime ADRS builders
    // ------------------------------------------------------------------

    /**
     * Emit runtime 18-byte ADRS prefix:
     * layer(1B) || PICK(treeAddr8)(8B) || type(1B) || PICK(keypair4)(4B) || chain(4B).
     *
     * <p>Net stack effect: +1.
     *
     * <p>{@code ta8Depth} and {@code kp4Depth} are from TOS *before* this
     * function pushes anything. {@code kp4Depth = -1} means push 4 zero bytes
     * instead of a PICK.
     */
    private static void emitBuildAdrs18(
        Consumer<StackOp> emit, int layer, int adrsType, int chain,
        int ta8Depth, int kp4Depth
    ) {
        emit.accept(pushBytes(new byte[]{(byte) (layer & 0xff)}));
        emit.accept(pushInt(ta8Depth + 1));
        emit.accept(new PickOp(ta8Depth + 1));
        emit.accept(new OpcodeOp("OP_CAT"));

        emit.accept(pushBytes(new byte[]{(byte) (adrsType & 0xff)}));
        emit.accept(new OpcodeOp("OP_CAT"));

        if (kp4Depth < 0) {
            emit.accept(pushBytes(new byte[4]));
        } else {
            emit.accept(pushInt(kp4Depth + 1));
            emit.accept(new PickOp(kp4Depth + 1));
        }
        emit.accept(new OpcodeOp("OP_CAT"));

        emit.accept(pushBytes(int4be(chain)));
        emit.accept(new OpcodeOp("OP_CAT"));
    }

    /** Hash-mode for the 22-byte ADRS builder. */
    private enum HashMode { ZERO, STACK }

    /**
     * Emit runtime 22-byte ADRS.
     *
     * <ul>
     *   <li>{@link HashMode#ZERO}: append 4 zero bytes (hash=0). Net +1.</li>
     *   <li>{@link HashMode#STACK}: TOS is a 4-byte BE hash; consumed and
     *       appended. Net 0.</li>
     * </ul>
     */
    private static void emitBuildAdrs(
        Consumer<StackOp> emit, int layer, int adrsType, int chain,
        int ta8Depth, int kp4Depth, HashMode mode
    ) {
        if (mode == HashMode.STACK) {
            emit.accept(new OpcodeOp("OP_TOALTSTACK"));
            int adjKp4 = kp4Depth >= 0 ? kp4Depth - 1 : kp4Depth;
            emitBuildAdrs18(emit, layer, adrsType, chain, ta8Depth - 1, adjKp4);
            emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
            emit.accept(new OpcodeOp("OP_CAT"));
        } else {
            emitBuildAdrs18(emit, layer, adrsType, chain, ta8Depth, kp4Depth);
            emit.accept(pushBytes(new byte[4]));
            emit.accept(new OpcodeOp("OP_CAT"));
        }
    }

    // ------------------------------------------------------------------
    // 4. SLH stack tracker
    // ------------------------------------------------------------------

    /** Tracks named stack positions and emits {@link StackOp}s. */
    private static final class Tracker {
        final ArrayList<String> nm;
        final Consumer<StackOp> e;

        Tracker(List<String> init, Consumer<StackOp> emit) {
            this.nm = new ArrayList<>(init);
            this.e = emit;
        }

        int depth() { return nm.size(); }

        int findDepth(String name) {
            for (int i = nm.size() - 1; i >= 0; i--) {
                if (nm.get(i).equals(name)) {
                    return nm.size() - 1 - i;
                }
            }
            throw new RuntimeException("SLHTracker: '" + name + "' not on stack " + nm);
        }

        boolean has(String name) { return nm.contains(name); }

        void pushBytesNamed(String n, byte[] v) {
            e.accept(pushBytes(v));
            nm.add(n);
        }

        void pushIntNamed(String n, long v) {
            e.accept(pushInt(v));
            nm.add(n);
        }

        void pushEmpty(String n) {
            e.accept(new OpcodeOp("OP_0"));
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
                nm.set(L - 2, top);
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
                String tmp = nm.get(L - 1);
                nm.set(L - 1, nm.get(L - 2));
                nm.set(L - 2, tmp);
            }
        }

        void rot() {
            e.accept(new RotOp());
            int L = nm.size();
            if (L >= 3) {
                String r = nm.remove(L - 3);
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
            e.accept(pushInt(d));
            nm.add("");
            e.accept(new OpcodeOp("OP_ROLL"));
            nm.remove(nm.size() - 1); // pop the push
            int idx = nm.size() - 1 - d;
            String r = nm.remove(idx);
            nm.add(r);
        }

        void pick(int d, String n) {
            if (d == 0) { dup(n); return; }
            if (d == 1) { over(n); return; }
            e.accept(pushInt(d));
            nm.add("");
            e.accept(new OpcodeOp("OP_PICK"));
            nm.remove(nm.size() - 1); // pop the push
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

        void split(String left, String right) {
            op("OP_SPLIT");
            if (!nm.isEmpty()) nm.remove(nm.size() - 1);
            if (!nm.isEmpty()) nm.remove(nm.size() - 1);
            nm.add(left);
            nm.add(right);
        }

        void cat(String n) {
            op("OP_CAT");
            int L = nm.size();
            if (L >= 2) {
                nm.remove(L - 1);
                nm.remove(L - 2);
            }
            nm.add(n);
        }

        void sha256(String n) {
            op("OP_SHA256");
            if (!nm.isEmpty()) nm.remove(nm.size() - 1);
            nm.add(n);
        }

        void equal(String n) {
            op("OP_EQUAL");
            int L = nm.size();
            if (L >= 2) {
                nm.remove(L - 1);
                nm.remove(L - 2);
            }
            nm.add(n);
        }

        void rename(String n) {
            if (!nm.isEmpty()) nm.set(nm.size() - 1, n);
        }

        /** Emit raw opcodes; tracker only records net stack effect. */
        void rawBlock(List<String> consume, String produce, Consumer<Consumer<StackOp>> fn) {
            for (int i = 0; i < consume.size(); i++) {
                if (!nm.isEmpty()) nm.remove(nm.size() - 1);
            }
            fn.accept(e);
            if (produce != null && !produce.isEmpty()) {
                nm.add(produce);
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. Tweakable hash T(pkSeed, ADRS, M)
    // ------------------------------------------------------------------

    /**
     * Raw tweakable hash with pkSeedPad on main stack via PICK.
     *
     * <p>Stack in:  {@code adrsC(1) msg(0)}, pkSeedPad at depth {@code pkSeedPadDepth}.
     * Stack out: {@code result(0)}.
     */
    private static void emitSlhTRaw(Consumer<StackOp> e, int n, int pkSeedPadDepth) {
        e.accept(new OpcodeOp("OP_CAT"));
        int pickDepth = pkSeedPadDepth - 1;
        e.accept(pushInt(pickDepth));
        e.accept(new PickOp(pickDepth));
        e.accept(new SwapOp());
        e.accept(new OpcodeOp("OP_CAT"));
        e.accept(new OpcodeOp("OP_SHA256"));
        if (n < 32) {
            e.accept(pushInt(n));
            e.accept(new OpcodeOp("OP_SPLIT"));
            e.accept(new DropOp());
        }
    }

    // ------------------------------------------------------------------
    // 6. WOTS+ one chain (tweakable hash, dynamic hashAddress)
    // ------------------------------------------------------------------

    /**
     * One conditional hash step (if-then body).
     *
     * <p>Entry: {@code sigElem(2) steps(1) hashAddr(0)}.
     * Exit:  {@code newSigElem(2) (steps-1)(1) (hashAddr+1)(0)}.
     */
    private static List<StackOp> slhChainStepThen(int n, int pkSeedPadDepth) {
        List<StackOp> ops = new ArrayList<>();
        // DUP hashAddr before consuming it in ADRS construction
        ops.add(new DupOp());
        // Convert copy to 4-byte big-endian
        ops.add(pushInt(4));
        ops.add(new OpcodeOp("OP_NUM2BIN"));
        ops.addAll(emitReverseN(4));

        // Get prefix from alt: FROMALT; DUP; TOALT
        ops.add(new OpcodeOp("OP_FROMALTSTACK"));
        ops.add(new OpcodeOp("OP_DUP"));
        ops.add(new OpcodeOp("OP_TOALTSTACK"));
        ops.add(new SwapOp());
        ops.add(new OpcodeOp("OP_CAT"));

        // Move sigElem to top: ROLL 3
        ops.add(pushInt(3));
        ops.add(new RollOp(3));
        ops.add(new OpcodeOp("OP_CAT"));

        // pkSeedPad via PICK
        ops.add(pushInt(pkSeedPadDepth));
        ops.add(new PickOp(pkSeedPadDepth));
        ops.add(new SwapOp());
        ops.add(new OpcodeOp("OP_CAT"));
        ops.add(new OpcodeOp("OP_SHA256"));
        if (n < 32) {
            ops.add(pushInt(n));
            ops.add(new OpcodeOp("OP_SPLIT"));
            ops.add(new DropOp());
        }
        // Rearrange
        ops.add(new RotOp());
        ops.add(new OpcodeOp("OP_1SUB"));
        ops.add(new RotOp());
        ops.add(new OpcodeOp("OP_1ADD"));
        return ops;
    }

    /**
     * Emit one WOTS+ chain with tweakable hashing (raw opcodes).
     *
     * <p>Input:  {@code sig(3) csum(2) endptAcc(1) digit(0)}.
     * Output: {@code sigRest(2) newCsum(1) newEndptAcc(0)}.
     */
    private static void emitSlhOneChain(
        Consumer<StackOp> emit, int n, int layer, int chainIdx,
        int pkSeedPadDepth, int ta8Depth, int kp4Depth
    ) {
        // steps = 15 - digit
        emit.accept(pushInt(15));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_SUB"));

        // Save steps_copy, endptAcc, csum to alt
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        // Split n-byte sig element
        emit.accept(new SwapOp());
        emit.accept(pushInt(n));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));
        emit.accept(new SwapOp());

        // Compute hashAddr = 15 - steps (= digit)
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(pushInt(15));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_SUB"));

        int pspDChain = pkSeedPadDepth - 1;
        int ta8DChain = ta8Depth - 1;
        int kp4DChain = kp4Depth - 1;

        // Build 18-byte ADRS prefix
        emitBuildAdrs18(emit, layer, SLH_WOTS_HASH, chainIdx, ta8DChain, kp4DChain);
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        // Build then-ops for chain step
        List<StackOp> thenOps = slhChainStepThen(n, pspDChain);

        // 15 unrolled conditional hash iterations
        for (int i = 0; i < 15; i++) {
            emit.accept(new OverOp());
            emit.accept(new OpcodeOp("OP_0NOTEQUAL"));
            emit.accept(new IfOp(thenOps));
        }

        emit.accept(new DropOp());
        emit.accept(new DropOp());

        // Drop prefix from alt
        emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
        emit.accept(new DropOp());

        // Restore from alt (LIFO)
        emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // sigRest
        emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // csum
        emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // endptAcc
        emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // steps_copy

        // csum += steps_copy
        emit.accept(new RotOp());
        emit.accept(new OpcodeOp("OP_ADD"));

        // Cat endpoint to endptAcc
        emit.accept(new SwapOp());
        emit.accept(pushInt(3));
        emit.accept(new RollOp(3));
        emit.accept(new OpcodeOp("OP_CAT"));
    }

    // ------------------------------------------------------------------
    // 7. Full WOTS+ processing (all len chains)
    // ------------------------------------------------------------------

    /**
     * Process all WOTS+ chains.
     *
     * <p>Input:  {@code psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)}.
     * Output: {@code psp(3) ta8(2) kp4(1) wotsPk(0)}.
     */
    private static void emitSlhWotsAll(Consumer<StackOp> emit, SLHCodegenParams p, int layer) {
        int n = p.n;
        int len1 = p.len1;
        int len2 = p.len2;

        emit.accept(new SwapOp());
        emit.accept(pushInt(0));
        emit.accept(new OpcodeOp("OP_0"));
        emit.accept(pushInt(3));
        emit.accept(new RollOp(3));

        for (int byteIdx = 0; byteIdx < n; byteIdx++) {
            if (byteIdx < n - 1) {
                emit.accept(pushInt(1));
                emit.accept(new OpcodeOp("OP_SPLIT"));
                emit.accept(new SwapOp());
            }
            // Unsigned byte conversion
            emit.accept(pushInt(0));
            emit.accept(pushInt(1));
            emit.accept(new OpcodeOp("OP_NUM2BIN"));
            emit.accept(new OpcodeOp("OP_CAT"));
            emit.accept(new OpcodeOp("OP_BIN2NUM"));
            // High/low nibbles
            emit.accept(new OpcodeOp("OP_DUP"));
            emit.accept(pushInt(16));
            emit.accept(new OpcodeOp("OP_DIV"));
            emit.accept(new SwapOp());
            emit.accept(pushInt(16));
            emit.accept(new OpcodeOp("OP_MOD"));

            if (byteIdx < n - 1) {
                emit.accept(new OpcodeOp("OP_TOALTSTACK")); // loNib -> alt
                emit.accept(new SwapOp());
                emit.accept(new OpcodeOp("OP_TOALTSTACK")); // msgRest -> alt
            } else {
                emit.accept(new OpcodeOp("OP_TOALTSTACK")); // loNib -> alt
            }

            // First chain call (hiNib)
            emitSlhOneChain(emit, n, layer, byteIdx * 2, 6, 5, 4);

            if (byteIdx < n - 1) {
                emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // msgRest
                emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // loNib
                emit.accept(new SwapOp());
                emit.accept(new OpcodeOp("OP_TOALTSTACK"));   // msgRest -> alt
            } else {
                emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // loNib
            }

            // Second chain call (loNib)
            emitSlhOneChain(emit, n, layer, byteIdx * 2 + 1, 6, 5, 4);

            if (byteIdx < n - 1) {
                emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // msgRest
            }
        }

        // Checksum digits
        emit.accept(new SwapOp());

        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(pushInt(16));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(pushInt(16));
        emit.accept(new OpcodeOp("OP_DIV"));
        emit.accept(pushInt(16));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        emit.accept(pushInt(256));
        emit.accept(new OpcodeOp("OP_DIV"));
        emit.accept(pushInt(16));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        for (int ci = 0; ci < len2; ci++) {
            emit.accept(new OpcodeOp("OP_TOALTSTACK"));    // endptAcc -> alt
            emit.accept(pushInt(0));
            emit.accept(new OpcodeOp("OP_FROMALTSTACK"));  // endptAcc
            emit.accept(new OpcodeOp("OP_FROMALTSTACK"));  // digit

            emitSlhOneChain(emit, n, layer, len1 + ci, 6, 5, 4);

            emit.accept(new SwapOp());
            emit.accept(new DropOp());
        }

        emit.accept(new SwapOp());
        emit.accept(new DropOp());

        // Compress -> wotsPk
        emitBuildAdrs(emit, layer, SLH_WOTS_PK, 0, 2, -1, HashMode.ZERO);
        emit.accept(new SwapOp());
        emitSlhTRaw(emit, n, 4);
    }

    // ------------------------------------------------------------------
    // 8. Merkle auth path verification
    // ------------------------------------------------------------------

    /**
     * Merkle auth path verification.
     *
     * <p>Input:  {@code psp(5) ta8(4) kp4(3) leafIdx(2) authPath(hp*n)(1) node(n)(0)}.
     * Output: {@code psp(3) ta8(2) kp4(1) root(0)}.
     */
    private static void emitSlhMerkle(Consumer<StackOp> emit, SLHCodegenParams p, int layer) {
        int n = p.n;
        int hp = p.hp;

        emit.accept(pushInt(2));
        emit.accept(new RollOp(2));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        for (int j = 0; j < hp; j++) {
            emit.accept(new OpcodeOp("OP_TOALTSTACK")); // node -> alt
            emit.accept(pushInt(n));
            emit.accept(new OpcodeOp("OP_SPLIT"));
            emit.accept(new SwapOp());
            emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // node

            emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
            emit.accept(new OpcodeOp("OP_DUP"));
            emit.accept(new OpcodeOp("OP_TOALTSTACK"));

            if (j > 0) {
                emit.accept(pushBigInt(BigInteger.ONE.shiftLeft(j)));
                emit.accept(new OpcodeOp("OP_DIV"));
            }
            emit.accept(pushInt(2));
            emit.accept(new OpcodeOp("OP_MOD"));

            int jVal = j;
            List<StackOp> mkTweakOps = collectOps(e -> {
                e.accept(new OpcodeOp("OP_FROMALTSTACK"));
                e.accept(new OpcodeOp("OP_DUP"));
                e.accept(new OpcodeOp("OP_TOALTSTACK"));
                if (jVal + 1 > 0) {
                    e.accept(pushBigInt(BigInteger.ONE.shiftLeft(jVal + 1)));
                    e.accept(new OpcodeOp("OP_DIV"));
                }
                e.accept(pushInt(4));
                e.accept(new OpcodeOp("OP_NUM2BIN"));
                for (StackOp r : emitReverseN(4)) e.accept(r);
                emitBuildAdrs(e, layer, SLH_TREE, jVal + 1, 4, -1, HashMode.STACK);
                e.accept(new SwapOp());
                emitSlhTRaw(e, n, 5);
            });

            List<StackOp> thenBranch = new ArrayList<>(mkTweakOps.size() + 1);
            thenBranch.add(new OpcodeOp("OP_CAT"));
            thenBranch.addAll(mkTweakOps);

            List<StackOp> elseBranch = new ArrayList<>(mkTweakOps.size() + 2);
            elseBranch.add(new SwapOp());
            elseBranch.add(new OpcodeOp("OP_CAT"));
            elseBranch.addAll(mkTweakOps);

            emit.accept(new IfOp(thenBranch, elseBranch));
        }

        emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
        emit.accept(new DropOp());
        emit.accept(new SwapOp());
        emit.accept(new DropOp());
    }

    // ------------------------------------------------------------------
    // 9. FORS verification
    // ------------------------------------------------------------------

    /**
     * FORS verification.
     *
     * <p>Input:  {@code psp(4) ta8(3) kp4(2) forsSig(1) md(0)}.
     * Output: {@code psp(3) ta8(2) kp4(1) forsPk(0)}.
     */
    private static void emitSlhFors(Consumer<StackOp> emit, SLHCodegenParams p) {
        int n = p.n;
        int a = p.a;
        int k = p.k;

        emit.accept(new OpcodeOp("OP_TOALTSTACK")); // md -> alt
        emit.accept(new OpcodeOp("OP_0"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK")); // rootAcc -> alt

        for (int i = 0; i < k; i++) {
            // Get md
            emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // rootAcc
            emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // md
            emit.accept(new OpcodeOp("OP_DUP"));
            emit.accept(new OpcodeOp("OP_TOALTSTACK"));   // md back
            emit.accept(new SwapOp());
            emit.accept(new OpcodeOp("OP_TOALTSTACK"));   // rootAcc back

            // Extract idx
            int bitStart = i * a;
            int byteStart = bitStart / 8;
            int bitOffset = bitStart % 8;
            int bitsInFirst = Math.min(8 - bitOffset, a);
            int take = a <= bitsInFirst ? 1 : 2;

            if (byteStart > 0) {
                emit.accept(pushInt(byteStart));
                emit.accept(new OpcodeOp("OP_SPLIT"));
                emit.accept(new NipOp());
            }
            emit.accept(pushInt(take));
            emit.accept(new OpcodeOp("OP_SPLIT"));
            emit.accept(new DropOp());
            if (take > 1) {
                for (StackOp r : emitReverseN(take)) emit.accept(r);
            }
            emit.accept(pushInt(0));
            emit.accept(pushInt(1));
            emit.accept(new OpcodeOp("OP_NUM2BIN"));
            emit.accept(new OpcodeOp("OP_CAT"));
            emit.accept(new OpcodeOp("OP_BIN2NUM"));
            int totalBits = take * 8;
            int rightShift = totalBits - bitOffset - a;
            if (rightShift > 0) {
                emit.accept(pushBigInt(BigInteger.ONE.shiftLeft(rightShift)));
                emit.accept(new OpcodeOp("OP_DIV"));
            }
            emit.accept(pushBigInt(BigInteger.ONE.shiftLeft(a)));
            emit.accept(new OpcodeOp("OP_MOD"));

            // Save idx to alt
            emit.accept(new OpcodeOp("OP_TOALTSTACK"));

            // Split sk(n) from sigRem
            emit.accept(pushInt(n));
            emit.accept(new OpcodeOp("OP_SPLIT"));
            emit.accept(new SwapOp());

            // Leaf hash
            emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
            emit.accept(new OpcodeOp("OP_DUP"));
            emit.accept(new OpcodeOp("OP_TOALTSTACK"));

            if (i > 0) {
                emit.accept(pushBigInt(BigInteger.valueOf(i).shiftLeft(a)));
                emit.accept(new OpcodeOp("OP_ADD"));
            }
            emit.accept(pushInt(4));
            emit.accept(new OpcodeOp("OP_NUM2BIN"));
            for (StackOp r : emitReverseN(4)) emit.accept(r);

            emitBuildAdrs(emit, 0, SLH_FORS_TREE, 0, 4, 3, HashMode.STACK);
            emit.accept(new SwapOp());
            emitSlhTRaw(emit, n, 5);

            // Auth path walk: a levels
            for (int j = 0; j < a; j++) {
                emit.accept(new OpcodeOp("OP_TOALTSTACK")); // node -> alt
                emit.accept(pushInt(n));
                emit.accept(new OpcodeOp("OP_SPLIT"));
                emit.accept(new SwapOp());
                emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // node

                emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
                emit.accept(new OpcodeOp("OP_DUP"));
                emit.accept(new OpcodeOp("OP_TOALTSTACK"));

                if (j > 0) {
                    emit.accept(pushBigInt(BigInteger.ONE.shiftLeft(j)));
                    emit.accept(new OpcodeOp("OP_DIV"));
                }
                emit.accept(pushInt(2));
                emit.accept(new OpcodeOp("OP_MOD"));

                int iVal = i;
                int jVal = j;
                int aVal = a;
                List<StackOp> mkForsAuth = collectOps(e -> {
                    e.accept(new OpcodeOp("OP_FROMALTSTACK"));
                    e.accept(new OpcodeOp("OP_DUP"));
                    e.accept(new OpcodeOp("OP_TOALTSTACK"));
                    if (jVal + 1 > 0) {
                        e.accept(pushBigInt(BigInteger.ONE.shiftLeft(jVal + 1)));
                        e.accept(new OpcodeOp("OP_DIV"));
                    }
                    BigInteger base = BigInteger.valueOf(iVal).shiftLeft(aVal - jVal - 1);
                    if (base.signum() > 0) {
                        e.accept(pushBigInt(base));
                        e.accept(new OpcodeOp("OP_ADD"));
                    }
                    e.accept(pushInt(4));
                    e.accept(new OpcodeOp("OP_NUM2BIN"));
                    for (StackOp r : emitReverseN(4)) e.accept(r);
                    emitBuildAdrs(e, 0, SLH_FORS_TREE, jVal + 1, 4, 3, HashMode.STACK);
                    e.accept(new SwapOp());
                    emitSlhTRaw(e, n, 5);
                });

                List<StackOp> thenBranch = new ArrayList<>(mkForsAuth.size() + 1);
                thenBranch.add(new OpcodeOp("OP_CAT"));
                thenBranch.addAll(mkForsAuth);

                List<StackOp> elseBranch = new ArrayList<>(mkForsAuth.size() + 2);
                elseBranch.add(new SwapOp());
                elseBranch.add(new OpcodeOp("OP_CAT"));
                elseBranch.addAll(mkForsAuth);

                emit.accept(new IfOp(thenBranch, elseBranch));
            }

            // Drop idx from alt
            emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
            emit.accept(new DropOp());

            // Append treeRoot to rootAcc
            emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // rootAcc
            emit.accept(new SwapOp());
            emit.accept(new OpcodeOp("OP_CAT"));
            emit.accept(new OpcodeOp("OP_TOALTSTACK")); // rootAcc -> alt
        }

        // Drop empty sigRest
        emit.accept(new DropOp());

        emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // rootAcc
        emit.accept(new OpcodeOp("OP_FROMALTSTACK")); // md
        emit.accept(new DropOp());

        // Compress
        emitBuildAdrs(emit, 0, SLH_FORS_ROOTS, 0, 2, 1, HashMode.ZERO);
        emit.accept(new SwapOp());
        emitSlhTRaw(emit, n, 4);
    }

    // ------------------------------------------------------------------
    // 10. Hmsg -- message digest (SHA-256 MGF1)
    // ------------------------------------------------------------------

    /**
     * Emit message digest computation.
     *
     * <p>Input:  {@code R(3) pkSeed(2) pkRoot(1) msg(0)}.
     * Output: {@code digest(outLen bytes)}.
     */
    private static void emitSlhHmsg(Consumer<StackOp> emit, int n, int outLen) {
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_SHA256"));

        int blocks = (outLen + 31) / 32;
        if (blocks == 1) {
            emit.accept(pushBytes(new byte[4]));
            emit.accept(new OpcodeOp("OP_CAT"));
            emit.accept(new OpcodeOp("OP_SHA256"));
            if (outLen < 32) {
                emit.accept(pushInt(outLen));
                emit.accept(new OpcodeOp("OP_SPLIT"));
                emit.accept(new DropOp());
            }
        } else {
            emit.accept(new OpcodeOp("OP_0")); // resultAcc
            emit.accept(new SwapOp());          // resultAcc seed

            for (int ctr = 0; ctr < blocks; ctr++) {
                if (ctr < blocks - 1) {
                    emit.accept(new OpcodeOp("OP_DUP"));
                }
                byte[] ctrBytes = new byte[]{
                    (byte) ((ctr >> 24) & 0xff),
                    (byte) ((ctr >> 16) & 0xff),
                    (byte) ((ctr >> 8) & 0xff),
                    (byte) (ctr & 0xff),
                };
                emit.accept(pushBytes(ctrBytes));
                emit.accept(new OpcodeOp("OP_CAT"));
                emit.accept(new OpcodeOp("OP_SHA256"));

                if (ctr == blocks - 1) {
                    int rem = outLen - ctr * 32;
                    if (rem < 32) {
                        emit.accept(pushInt(rem));
                        emit.accept(new OpcodeOp("OP_SPLIT"));
                        emit.accept(new DropOp());
                    }
                }

                if (ctr < blocks - 1) {
                    emit.accept(new RotOp());
                    emit.accept(new SwapOp());
                    emit.accept(new OpcodeOp("OP_CAT"));
                    emit.accept(new SwapOp());
                } else {
                    emit.accept(new SwapOp());
                    emit.accept(new OpcodeOp("OP_CAT"));
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 11. Main verifier
    // ------------------------------------------------------------------

    private static void emitVerifySlhDsaInternal(Consumer<StackOp> emit, SLHCodegenParams p) {
        int n = p.n;
        int d = p.d;
        int hp = p.hp;
        int k = p.k;
        int a = p.a;
        int ln = p.len;
        int forsSigLen = k * (1 + a) * n;
        int xmssSigLen = (ln + hp) * n;
        int mdLen = (k * a + 7) / 8;
        int treeIdxLen = (p.h - hp + 7) / 8;
        int leafIdxLen = (hp + 7) / 8;
        int digestLen = mdLen + treeIdxLen + leafIdxLen;

        Tracker t = new Tracker(Arrays.asList("msg", "sig", "pubkey"), emit);

        // ---- 1. Parse pubkey -> pkSeed, pkRoot ----
        t.toTop("pubkey");
        t.pushIntNamed("", n);
        t.split("pkSeed", "pkRoot");

        // Build pkSeedPad
        t.copyToTop("pkSeed", "_psp");
        if (64 - n > 0) {
            t.pushBytesNamed("", new byte[64 - n]);
            t.cat("_pkSeedPad");
        } else {
            t.rename("_pkSeedPad");
        }

        // ---- 2. Parse R from sig ----
        t.toTop("sig");
        t.pushIntNamed("", n);
        t.split("R", "sigRest");

        // ---- 3. Compute Hmsg(R, pkSeed, pkRoot, msg) ----
        t.copyToTop("R", "_R");
        t.copyToTop("pkSeed", "_pks");
        t.copyToTop("pkRoot", "_pkr");
        t.copyToTop("msg", "_msg");
        final int digestLenF = digestLen;
        final int nF = n;
        t.rawBlock(List.of("_R", "_pks", "_pkr", "_msg"), "digest",
            e -> emitSlhHmsg(e, nF, digestLenF));

        // ---- 4. Extract md, treeIdx, leafIdx ----
        t.toTop("digest");
        t.pushIntNamed("", mdLen);
        t.split("md", "_drest");

        t.toTop("_drest");
        t.pushIntNamed("", treeIdxLen);
        t.split("_treeBytes", "_leafBytes");

        // Convert _treeBytes -> treeIdx
        t.toTop("_treeBytes");
        final int treeIdxLenF = treeIdxLen;
        final int hF = p.h;
        final int hpF = hp;
        Consumer<Consumer<StackOp>> convertTree = e -> {
            if (treeIdxLenF > 1) {
                for (StackOp r : emitReverseN(treeIdxLenF)) e.accept(r);
            }
            e.accept(pushInt(0));
            e.accept(pushInt(1));
            e.accept(new OpcodeOp("OP_NUM2BIN"));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
            BigInteger modulus = BigInteger.ONE.shiftLeft(hF - hpF);
            e.accept(pushBigInt(modulus));
            e.accept(new OpcodeOp("OP_MOD"));
        };
        t.rawBlock(List.of("_treeBytes"), "treeIdx", convertTree);

        // Convert _leafBytes -> leafIdx
        t.toTop("_leafBytes");
        final int leafIdxLenF = leafIdxLen;
        Consumer<Consumer<StackOp>> convertLeaf = e -> {
            if (leafIdxLenF > 1) {
                for (StackOp r : emitReverseN(leafIdxLenF)) e.accept(r);
            }
            e.accept(pushInt(0));
            e.accept(pushInt(1));
            e.accept(new OpcodeOp("OP_NUM2BIN"));
            e.accept(new OpcodeOp("OP_CAT"));
            e.accept(new OpcodeOp("OP_BIN2NUM"));
            e.accept(pushBigInt(BigInteger.ONE.shiftLeft(hpF)));
            e.accept(new OpcodeOp("OP_MOD"));
        };
        t.rawBlock(List.of("_leafBytes"), "leafIdx", convertLeaf);

        // ---- 4b. Compute treeAddr8 and keypair4 ----
        t.copyToTop("treeIdx", "_ti8");
        Consumer<Consumer<StackOp>> treeAddr = e -> {
            e.accept(pushInt(8));
            e.accept(new OpcodeOp("OP_NUM2BIN"));
            for (StackOp r : emitReverseN(8)) e.accept(r);
        };
        t.rawBlock(List.of("_ti8"), "treeAddr8", treeAddr);

        t.copyToTop("leafIdx", "_li4");
        Consumer<Consumer<StackOp>> keypairAddr = e -> {
            e.accept(pushInt(4));
            e.accept(new OpcodeOp("OP_NUM2BIN"));
            for (StackOp r : emitReverseN(4)) e.accept(r);
        };
        t.rawBlock(List.of("_li4"), "keypair4", keypairAddr);

        // ---- 5. Parse FORS sig ----
        t.toTop("sigRest");
        t.pushIntNamed("", forsSigLen);
        t.split("forsSig", "htSigRest");

        // ---- 6. FORS -> forsPk ----
        t.copyToTop("_pkSeedPad", "_psp");
        t.copyToTop("treeAddr8", "_ta");
        t.copyToTop("keypair4", "_kp");
        t.toTop("forsSig");
        t.toTop("md");
        final SLHCodegenParams pF = p;
        Consumer<Consumer<StackOp>> forsBlock = e -> {
            emitSlhFors(e, pF);
            e.accept(new OpcodeOp("OP_TOALTSTACK"));
            e.accept(new DropOp());
            e.accept(new DropOp());
            e.accept(new DropOp());
            e.accept(new OpcodeOp("OP_FROMALTSTACK"));
        };
        t.rawBlock(List.of("_psp", "_ta", "_kp", "forsSig", "md"), "forsPk", forsBlock);

        // ---- 7. Hypertree: d layers ----
        for (int layer = 0; layer < d; layer++) {
            t.toTop("htSigRest");
            t.pushIntNamed("", xmssSigLen);
            t.split("xsig" + layer, "htSigRest");

            t.toTop("xsig" + layer);
            t.pushIntNamed("", ln * n);
            t.split("wsig" + layer, "auth" + layer);

            String curMsg = layer == 0 ? "forsPk" : ("root" + (layer - 1));
            t.copyToTop("_pkSeedPad", "_psp");
            t.copyToTop("treeAddr8", "_ta");
            t.copyToTop("keypair4", "_kp");
            String wsigName = "wsig" + layer;
            t.toTop(wsigName);
            t.toTop(curMsg);
            String wpkName = "wpk" + layer;

            final int layerVal = layer;
            Consumer<Consumer<StackOp>> wotsBlock = e -> {
                emitSlhWotsAll(e, pF, layerVal);
                e.accept(new OpcodeOp("OP_TOALTSTACK"));
                e.accept(new DropOp());
                e.accept(new DropOp());
                e.accept(new DropOp());
                e.accept(new OpcodeOp("OP_FROMALTSTACK"));
            };
            t.rawBlock(List.of("_psp", "_ta", "_kp", wsigName, curMsg), wpkName, wotsBlock);

            // Merkle
            t.copyToTop("_pkSeedPad", "_psp");
            t.copyToTop("treeAddr8", "_ta");
            t.copyToTop("keypair4", "_kp");
            t.toTop("leafIdx");
            String authName = "auth" + layer;
            t.toTop(authName);
            t.toTop(wpkName);
            String rootName = "root" + layer;

            Consumer<Consumer<StackOp>> merkleBlock = e -> {
                emitSlhMerkle(e, pF, layerVal);
                e.accept(new OpcodeOp("OP_TOALTSTACK"));
                e.accept(new DropOp());
                e.accept(new DropOp());
                e.accept(new DropOp());
                e.accept(new OpcodeOp("OP_FROMALTSTACK"));
            };
            t.rawBlock(List.of("_psp", "_ta", "_kp", "leafIdx", authName, wpkName),
                       rootName, merkleBlock);

            // Update leafIdx, treeIdx, treeAddr8, keypair4 for next layer
            if (layer < d - 1) {
                t.toTop("treeIdx");
                t.dup("_tic");
                Consumer<Consumer<StackOp>> newLeaf = e -> {
                    e.accept(pushBigInt(BigInteger.ONE.shiftLeft(hpF)));
                    e.accept(new OpcodeOp("OP_MOD"));
                };
                t.rawBlock(List.of("_tic"), "leafIdx", newLeaf);
                t.swap();
                Consumer<Consumer<StackOp>> newTree = e -> {
                    e.accept(pushBigInt(BigInteger.ONE.shiftLeft(hpF)));
                    e.accept(new OpcodeOp("OP_DIV"));
                };
                t.rawBlock(List.of("treeIdx"), "treeIdx", newTree);

                t.toTop("treeAddr8");
                t.drop();
                t.copyToTop("treeIdx", "_ti8");
                t.rawBlock(List.of("_ti8"), "treeAddr8", treeAddr);

                t.toTop("keypair4");
                t.drop();
                t.copyToTop("leafIdx", "_li4");
                t.rawBlock(List.of("_li4"), "keypair4", keypairAddr);
            }
        }

        // ---- 8. Compare root to pkRoot ----
        t.toTop("root" + (d - 1));
        t.toTop("pkRoot");
        t.equal("_result");

        // ---- 9. Cleanup ----
        t.toTop("_result");
        t.toAlt();

        List<String> leftover = List.of(
            "msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx",
            "_pkSeedPad", "treeAddr8", "keypair4"
        );
        for (String nm : leftover) {
            if (t.has(nm)) {
                t.toTop(nm);
                t.drop();
            }
        }
        while (t.depth() > 0) {
            t.drop();
        }

        t.fromAlt("_result");
    }
}
