package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AddDataOutput;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AddRawOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.ArrayLiteral;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.ConstValue;
import runar.compiler.ir.anf.DeserializeState;
import runar.compiler.ir.anf.GetStateScript;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.RawScript;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.UnknownAnfKindError;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.NipOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PickOp;
import runar.compiler.ir.stack.PlaceholderOp;
import runar.compiler.ir.stack.PushCodeSepIndexOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.RawBytesOp;
import runar.compiler.ir.stack.RollOp;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.SwapOp;

/**
 * ANF → Stack IR lowering (Pass 5).
 *
 * <p>Port of {@code compilers/python/runar_compiler/codegen/stack.py} and
 * {@code packages/runar-compiler/src/passes/05-stack-lower.ts}. Each ANF
 * method is flattened to a linear stream of {@link StackOp}s while tracking
 * a per-method {@code StackMap} of named temporaries on the stack.
 *
 * <p>The algorithm walks each binding, brings its operand temporaries to
 * top-of-stack via {@code DUP}/{@code SWAP}/{@code PICK}/{@code ROLL} (or
 * their canned equivalents for small depths), and emits the op(s) that
 * implement the binding's semantics.
 */
public final class StackLower {

    private StackLower() {}

    private static final int MAX_STACK_DEPTH = 800;


    private static int trailingMergedLocalResults(List<AnfBinding> bindings) {
        String prefix = "@ref:" + AnfValue.MERGED_LOCAL_TEMP_PREFIX;
        int n = 0;
        for (int i = bindings.size() - 1; i >= 0; i--) {
            AnfValue v = bindings.get(i).value();
            if (!(v instanceof LoadConst lc)) break;
            if (!(lc.value() instanceof BytesConst bc)) break;
            if (!bc.hex().startsWith(prefix)) break;
            n++;
        }
        return n;
    }

    /**
     * OP_PUSH_TX on-chain signature derivation (BUG-100 fix).
     *
     * <p>The insecure legacy checkPreimage accepted a witness signature over the
     * real spending transaction and checked it against pubkey G, never reading
     * the pushed preimage — so the preimage was decoupled from the tx. This
     * derives the ECDSA signature FROM the preimage on-chain (s = (hash256(
     * preimage) + r)*kinv mod n, fixed nonce, privkey d=1, low-S, minimal DER),
     * so OP_CHECKSIG passes only when hash256(preimage) equals the real tx
     * sighash.
     *
     * <p>The construction compiles to a FIXED byte sequence identical across all
     * seven tiers; it is the canonical output of the TypeScript reference
     * (packages/runar-compiler/src/passes/oppushtx-codegen.ts). Emitted as a
     * single opaque raw_bytes op (peephole barrier). The cross-tier conformance
     * suite guards that this constant matches every other tier byte-for-byte.
     */
    private static final String CHECK_PREIMAGE_BINDING_HEX =
        "76aa007c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e"
        + "7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f"
        + "7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c"
        + "7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c51"
        + "7f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b"
        + "7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c"
        + "7501007e8121e59e705cb909acaba73cef8c4b8e775cd87cc0956e4045306d7ded41947f04c6"
        + "009320a1201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f952141"
        + "4136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e977b757893"
        + "7c977620a0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7fa078"
        + "21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007c8d7c94"
        + "9594826b012080007c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c51"
        + "7f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b"
        + "7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c"
        + "517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b"
        + "7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e"
        + "7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f"
        + "7b7b7c7e7c756c01207c947f777682775180527c7e7c7e768277012393518023022100c6047f"
        + "9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50130527a7e7c7e7c7e"
        + "01417e210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad";

    /**
     * Issue #123: the check-preimage binding blob for a declared @sighash mode.
     * The default ALL|FORKID (null / 0x41) returns the pinned cross-tier
     * constant verbatim. A non-default mode swaps ONLY the appended sighash flag
     * byte — the unique {@code 01 41 7e} subsequence (OP_PUSHDATA(1) 0x41 OP_CAT)
     * that appends the flag to the derived DER signature — leaving every other
     * byte byte-identical to the default blob (matching the TypeScript reference
     * {@code checkPreimageBindingBytes(sighashFlag)}).
     */
    private static String checkPreimageBindingHex(Integer sighashFlag) {
        if (sighashFlag == null || sighashFlag == SighashDirective.SIGHASH_DEFAULT) {
            return CHECK_PREIMAGE_BINDING_HEX;
        }
        int marker = CHECK_PREIMAGE_BINDING_HEX.indexOf("01417e");
        if (marker < 0) {
            // Defensive: the constant is pinned, so this cannot happen.
            throw new IllegalStateException("check-preimage binding: sighash flag byte not found");
        }
        String flagHex = String.format("%02x", sighashFlag & 0xff);
        return CHECK_PREIMAGE_BINDING_HEX.substring(0, marker + 2)
            + flagHex
            + CHECK_PREIMAGE_BINDING_HEX.substring(marker + 4);
    }

    // ------------------------------------------------------------------
    // State-field type classification (mirrors stack.py)
    // ------------------------------------------------------------------

    private static final Set<String> NUMERIC_STATE_TYPES = Set.of(
        "bigint", "boolean", "RabinSig", "RabinPubKey"
    );
    private static final Set<String> VARIABLE_LENGTH_STATE_TYPES = Set.of(
        "ByteString", "Sig", "SigHashPreimage"
    );

    private static boolean isNumericStateType(String t) {
        return NUMERIC_STATE_TYPES.contains(t);
    }

    private static boolean isVariableLengthStateType(String t) {
        return VARIABLE_LENGTH_STATE_TYPES.contains(t);
    }

    // ------------------------------------------------------------------
    // Opcode maps
    // ------------------------------------------------------------------

    private static final Map<String, List<String>> BUILTIN_OPCODES = Map.ofEntries(
        Map.entry("sha256",        List.of("OP_SHA256")),
        Map.entry("ripemd160",     List.of("OP_RIPEMD160")),
        Map.entry("hash160",       List.of("OP_HASH160")),
        Map.entry("hash256",       List.of("OP_HASH256")),
        Map.entry("checkSig",      List.of("OP_CHECKSIG")),
        Map.entry("checkMultiSig", List.of("OP_CHECKMULTISIG")),
        Map.entry("len",           List.of("OP_SIZE")),
        Map.entry("cat",           List.of("OP_CAT")),
        Map.entry("num2bin",       List.of("OP_NUM2BIN")),
        Map.entry("bin2num",       List.of("OP_BIN2NUM")),
        Map.entry("abs",           List.of("OP_ABS")),
        Map.entry("min",           List.of("OP_MIN")),
        Map.entry("max",           List.of("OP_MAX")),
        Map.entry("within",        List.of("OP_WITHIN")),
        Map.entry("split",         List.of("OP_SPLIT")),
        Map.entry("left",          List.of("OP_SPLIT", "OP_DROP")),
        Map.entry("int2str",       List.of("OP_NUM2BIN")),
        Map.entry("bool",          List.of("OP_0NOTEQUAL")),
        Map.entry("unpack",        List.of("OP_BIN2NUM"))
    );

    private static final Map<String, List<String>> BINOP_OPCODES = Map.ofEntries(
        Map.entry("+",   List.of("OP_ADD")),
        Map.entry("-",   List.of("OP_SUB")),
        Map.entry("*",   List.of("OP_MUL")),
        Map.entry("/",   List.of("OP_DIV")),
        Map.entry("%",   List.of("OP_MOD")),
        Map.entry("===", List.of("OP_NUMEQUAL")),
        Map.entry("!==", List.of("OP_NUMEQUAL", "OP_NOT")),
        Map.entry("<",   List.of("OP_LESSTHAN")),
        Map.entry(">",   List.of("OP_GREATERTHAN")),
        Map.entry("<=",  List.of("OP_LESSTHANOREQUAL")),
        Map.entry(">=",  List.of("OP_GREATERTHANOREQUAL")),
        Map.entry("&&",  List.of("OP_BOOLAND")),
        Map.entry("||",  List.of("OP_BOOLOR")),
        Map.entry("&",   List.of("OP_AND")),
        Map.entry("|",   List.of("OP_OR")),
        Map.entry("^",   List.of("OP_XOR")),
        Map.entry("<<",  List.of("OP_LSHIFT")),
        Map.entry(">>",  List.of("OP_RSHIFT"))
    );

    private static final Map<String, List<String>> UNARYOP_OPCODES = Map.of(
        "!", List.of("OP_NOT"),
        "-", List.of("OP_NEGATE"),
        "~", List.of("OP_INVERT")
    );

    // Go-only Mode-3 STARK / FRI / Groth16 verifier builtins are now routed
    // through dedicated stub codegen modules (BabyBear, KoalaBear,
    // Poseidon2KoalaBear, Poseidon2Merkle, Bn254, Merkle, FiatShamirKb) in
    // runar.compiler.codegen — each module's dispatch() throws
    // UnsupportedOperationException with a CLAUDE.md pointer. See the
    // dispatch chain in lowerBuiltinCall(). The old GO_ONLY_BUILTINS Set
    // was removed in favour of module-presence parity with the other 5
    // non-Go tiers (TS / Rust / Python / Zig / Ruby).

    // ------------------------------------------------------------------
    // StackMap: tracks named values on the stack
    // ------------------------------------------------------------------

    static final class StackMap {
        final List<String> slots = new ArrayList<>();

        StackMap() {}

        StackMap(List<String> initial) {
            if (initial != null) slots.addAll(initial);
        }

        int depth() { return slots.size(); }

        void push(String name) { slots.add(name); }

        String pop() {
            if (slots.isEmpty()) throw new RuntimeException("stack underflow");
            return slots.remove(slots.size() - 1);
        }

        int findDepth(String name) {
            for (int i = slots.size() - 1; i >= 0; i--) {
                if (name.equals(slots.get(i))) return slots.size() - 1 - i;
            }
            return -1;
        }

        boolean has(String name) {
            for (String s : slots) {
                if (name.equals(s)) return true;
            }
            return false;
        }

        String removeAtDepth(int depthFromTop) {
            int idx = slots.size() - 1 - depthFromTop;
            if (idx < 0 || idx >= slots.size()) {
                throw new RuntimeException("invalid stack depth: " + depthFromTop);
            }
            return slots.remove(idx);
        }

        String peekAtDepth(int depthFromTop) {
            int idx = slots.size() - 1 - depthFromTop;
            if (idx < 0 || idx >= slots.size()) {
                throw new RuntimeException("invalid stack depth: " + depthFromTop);
            }
            return slots.get(idx);
        }

        StackMap clone0() {
            StackMap sm = new StackMap();
            sm.slots.addAll(this.slots);
            return sm;
        }

        void swap() {
            int n = slots.size();
            if (n < 2) throw new RuntimeException("stack underflow on swap");
            String t = slots.get(n - 1);
            slots.set(n - 1, slots.get(n - 2));
            slots.set(n - 2, t);
        }

        void dup() {
            if (slots.isEmpty()) throw new RuntimeException("stack underflow on dup");
            slots.add(slots.get(slots.size() - 1));
        }

        void renameAtDepth(int depthFromTop, String newName) {
            int idx = slots.size() - 1 - depthFromTop;
            if (idx < 0 || idx >= slots.size()) {
                throw new RuntimeException("invalid stack depth for rename: " + depthFromTop);
            }
            slots.set(idx, newName == null ? "" : newName);
        }

        Set<String> namedSlots() {
            Set<String> out = new LinkedHashSet<>();
            for (String s : slots) if (s != null && !s.isEmpty()) out.add(s);
            return out;
        }

        /**
         * How many slots carry each name.
         *
         * <p>The model resolves a name to its SHALLOWEST slot, so a name held
         * more than once has one live slot and the rest are dead residue — but
         * they are all still "the name" to a set-membership test, which is what
         * NEW-018 turned on. See {@code lowerIf}. Insertion-ordered so callers
         * that iterate it stay deterministic.
         */
        Map<String, Integer> nameCounts() {
            Map<String, Integer> counts = new LinkedHashMap<>();
            for (String s : slots) {
                if (s != null && !s.isEmpty()) counts.merge(s, 1, Integer::sum);
            }
            return counts;
        }

        /**
         * The depths to drop for a MULTISET of names, deepest-first.
         *
         * <p>Takes the SHALLOWEST occurrences of a name listed more than once —
         * the shallowest slot is the live one, and it is the one the sibling arm
         * consumed. Deepest-first so removing a deeper slot does not shift a
         * shallower one. For a name listed once this is exactly
         * {@code findDepth}, which also resolves to the shallowest slot.
         */
        List<Integer> dropDepthsFor(List<String> names) {
            Map<String, Integer> need = new HashMap<>();
            for (String n : names) need.merge(n, 1, Integer::sum);
            List<Integer> depths = new ArrayList<>();
            for (int d = 0; d < depth(); d++) {
                String name = peekAtDepth(d);
                if (name == null || name.isEmpty()) continue;
                int want = need.getOrDefault(name, 0);
                if (want > 0) {
                    depths.add(d);
                    need.put(name, want - 1);
                }
            }
            depths.sort((a, b) -> Integer.compare(b, a));
            return depths;
        }

        /** Debug string of the slot names (bottom -> top) for error messages. */
        String debugSlots() {
            return String.join(", ", slots);
        }
    }

    // ------------------------------------------------------------------
    // Last-use analysis
    // ------------------------------------------------------------------

    static Map<String, Integer> computeLastUses(List<AnfBinding> bindings) {
        Map<String, Integer> lastUse = new HashMap<>();
        // Pre-scan: map each array_literal binding to its element refs. Used to
        // propagate last-use across the array indirection (the array binding is
        // pure metadata in lowerArrayLiteral — its elements must remain live
        // until the array's consumer, not until the array_literal binding itself).
        Map<String, List<String>> arrayElems = new HashMap<>();
        for (AnfBinding b : bindings) {
            if (b.value() instanceof ArrayLiteral al) {
                arrayElems.put(b.name(), new ArrayList<>(al.elements()));
            }
        }
        for (int i = 0; i < bindings.size(); i++) {
            AnfValue v = bindings.get(i).value();
            // array_literal is metadata-only — do NOT advance its elements'
            // last-use to here; defer to the array's consumer.
            if (v instanceof ArrayLiteral) {
                continue;
            }
            for (String r : collectRefs(v)) {
                lastUse.put(r, i);
                List<String> elems = arrayElems.get(r);
                if (elems != null) {
                    for (String e : elems) {
                        lastUse.put(e, i);
                    }
                }
            }
        }
        return lastUse;
    }

    /**
     * Collect every binding name defined anywhere in a binding sequence,
     * recursing into nested if-branches and loop bodies. Used by lowerLoop to
     * distinguish loop-internal (re)definitions from true outer-scope refs.
     */
    static Set<String> collectDeepBindingNames(List<AnfBinding> bindings) {
        Set<String> names = new LinkedHashSet<>();
        collectDeepBindingNamesInto(bindings, names);
        return names;
    }

    private static void collectDeepBindingNamesInto(List<AnfBinding> bindings, Set<String> names) {
        for (AnfBinding b : bindings) {
            names.add(b.name());
            if (b.value() instanceof If iv) {
                collectDeepBindingNamesInto(iv.thenBranch(), names);
                collectDeepBindingNamesInto(iv.elseBranch(), names);
            } else if (b.value() instanceof Loop l) {
                collectDeepBindingNamesInto(l.body(), names);
            }
        }
    }

    /**
     * Locals a loop body REBINDS and then READS AGAIN in the same iteration.
     *
     * <p>{@code computeLastUses} maps a name to the MAXIMUM index that
     * references it, so for a body like
     *
     * <pre>
     * t3   = acc + step     (index 1 — reads the value carried in)
     * acc  = &#64;ref:t3         (index 2 — rebinds: renames t3's slot to `acc`)
     * t4   = wacc + acc     (index 3 — reads the value just rebound)
     * </pre>
     *
     * <p>{@code acc} gets last-use 3. Index 1 is therefore NOT a last use and
     * copies (PICK) instead of consuming, leaving the incoming slot on the
     * stack under the same name as the rebound one; index 3 then IS the last
     * use, and findDepth resolves to the topmost match — so it consumes the
     * UPDATED value and leaves the dead incoming one. The next iteration reads
     * that dead slot, and every iteration recomputes from the pre-loop value:
     * {@code for (let i = 0n; i < N; i++) { acc = acc + step; wacc = wacc +
     * acc; }} produced {@code wacc = step*N} where the source says
     * {@code step*N*(N+1)/2} — silently in a stateless contract, and as a
     * permanently unspendable UTXO in a stateful one (the covenant commits to a
     * continuation the SDK never builds). {@code outerRefs} does not cover it:
     * {@code acc} is excluded there precisely because the body binds it.
     *
     * <p>The value these names hold at the end of an iteration is live at the
     * start of the next one, so lowerLoop protects them from consumption
     * exactly like an outer ref. The incoming slot each rebinding shadows is
     * left behind and drained with the rest of the frame at method exit — a
     * name always resolves to its newest slot, so the reads stay correct.
     *
     * <p>Both halves of the predicate are load-bearing:
     * <ul>
     *   <li>read BEFORE the first rebinding: the name is carried IN from the
     *       enclosing scope, rather than being a body-private temp that merely
     *       happens to be read after it is bound;</li>
     *   <li>read AFTER the last rebinding: without it the rebound value is dead
     *       at the end of the iteration and consuming it is correct. This is
     *       what keeps every shipped accumulator ({@code sum = sum + i},
     *       {@code off = off + len}) byte-for-byte unchanged.</li>
     * </ul>
     *
     * <p>NESTED loops: the scan runs over {@code flattenNestedLoopBodies(body)},
     * not over {@code body} itself. A name rebound only inside an INNER loop is
     * bound at no top-level index of the outer body, so the raw scan classified
     * it as neither an outer ref ({@code collectDeepBindingNames} excludes it —
     * the body does bind it, deeply) nor a carried rebind, and the outer loop
     * never marked it live. The inner loop's final iteration then consumed it,
     * because {@code usedAfterLoop} asks the enclosing scope and the enclosing
     * scope had not been told either, so every outer iteration restarted from
     * the slot the previous one left behind:
     * {@code for (i<2) { for (j<2) { acc = acc + step; wacc = wacc + acc; } }}
     * with step = 3 produced {@code wacc = 24} where the source says 30.
     * Splicing the inner body in at the loop's position preserves the
     * read/rebind/read ordering the inner level already sees, so the outer
     * level draws the same conclusion.
     */
    static Set<String> collectLoopCarriedRebinds(List<AnfBinding> body) {
        List<AnfBinding> flat = flattenNestedLoopBodies(body);

        Map<String, Integer> firstBind = new HashMap<>();
        Map<String, Integer> lastBind = new HashMap<>();
        for (int i = 0; i < flat.size(); i++) {
            String name = flat.get(i).name();
            firstBind.putIfAbsent(name, i);
            lastBind.put(name, i);
        }

        Set<String> readBeforeBind = new LinkedHashSet<>();
        Set<String> readAfterBind = new LinkedHashSet<>();
        for (int i = 0; i < flat.size(); i++) {
            for (String ref : collectRefs(flat.get(i).value())) {
                Integer first = firstBind.get(ref);
                if (first != null && i < first) readBeforeBind.add(ref);
                Integer last = lastBind.get(ref);
                if (last != null && i > last) readAfterBind.add(ref);
            }
        }

        readBeforeBind.retainAll(readAfterBind);
        return readBeforeBind;
    }

    /**
     * The binding sequence with every nested {@code loop} binding — and every
     * {@code if} binding — replaced, in place, by its own (recursively
     * flattened) body.
     *
     * <p>Only {@code collectLoopCarriedRebinds} uses this, and only to order
     * reads against rebindings. Neither replaced binding contributes a stack
     * slot that predicate reasons about, so dropping it loses nothing; splicing
     * the sub-body in at its position is what lets an enclosing loop see a
     * rebinding one level down.
     *
     * <p>{@code if} arms ARE spliced, in {@code then ++ else} order, even
     * though they are alternatives rather than a sequence. The predicate asks
     * only "is this name read, then rebound, then read again", and treating the
     * arms as a sequence can only ADD names to the carried set, never remove
     * one — conservative in the safe direction. Without it a local rebound ONLY
     * inside an {@code if} arm was bound at no index the predicate could see:
     * neither an outer ref ({@code collectDeepBindingNames} excludes it, since
     * the body does bind it, deeply) nor a carried rebind. The loop consumed it
     * and the next iteration had nothing to read, so
     * {@code for (i<2) { if (i<5) { acc = acc + step; } wacc = wacc + acc; }}
     * was REJECTED outright with {@code Value 'acc' not found on stack} — the
     * loud face of the same gap the merged-local protection in {@code lowerIf}
     * fixes silently at K&gt;=2.
     *
     * <p>The {@code if} binding itself is NOT re-appended after its arms.
     * Appending it would count the arms' reads a second time at an index past
     * every arm rebinding, making a local that BOTH arms rebind look "read
     * after its last rebinding" — which protected a K=1 alias that must stay
     * consumable.
     *
     * <p>A body with no nested loop and no {@code if} is returned
     * entry-for-entry unchanged, which is what makes this byte-neutral for
     * every flat loop.
     */
    static List<AnfBinding> flattenNestedLoopBodies(List<AnfBinding> body) {
        boolean nested = false;
        for (AnfBinding b : body) {
            if (b.value() instanceof Loop || b.value() instanceof If) {
                nested = true;
                break;
            }
        }
        if (!nested) return body;
        List<AnfBinding> flat = new ArrayList<>(body.size());
        for (AnfBinding b : body) {
            if (b.value() instanceof Loop l) {
                flat.addAll(flattenNestedLoopBodies(l.body()));
            } else if (b.value() instanceof If iv) {
                flat.addAll(flattenNestedLoopBodies(iv.thenBranch()));
                flat.addAll(flattenNestedLoopBodies(iv.elseBranch()));
            } else {
                flat.add(b);
            }
        }
        return flat;
    }

    static List<String> collectRefs(AnfValue value) {
        List<String> refs = new ArrayList<>();
        if (value instanceof LoadParam lp) {
            refs.add(lp.name());
        } else if (value instanceof LoadProp || value instanceof GetStateScript) {
            // no refs
        } else if (value instanceof LoadConst lc) {
            if (lc.value() instanceof BytesConst bc
                && bc.hex().length() > 5
                && bc.hex().startsWith("@ref:")) {
                refs.add(bc.hex().substring(5));
            }
        } else if (value instanceof BinOp bo) {
            refs.add(bo.left());
            refs.add(bo.right());
        } else if (value instanceof UnaryOp uo) {
            refs.add(uo.operand());
        } else if (value instanceof Call c) {
            refs.addAll(c.args());
        } else if (value instanceof MethodCall mc) {
            refs.add(mc.object());
            refs.addAll(mc.args());
        } else if (value instanceof If iv) {
            refs.add(iv.cond());
            for (AnfBinding b : iv.thenBranch()) refs.addAll(collectRefs(b.value()));
            for (AnfBinding b : iv.elseBranch()) refs.addAll(collectRefs(b.value()));
        } else if (value instanceof Loop l) {
            for (AnfBinding b : l.body()) refs.addAll(collectRefs(b.value()));
        } else if (value instanceof Assert a) {
            refs.add(a.value());
        } else if (value instanceof UpdateProp up) {
            refs.add(up.value());
        } else if (value instanceof CheckPreimage cp) {
            refs.add(cp.preimage());
        } else if (value instanceof DeserializeState ds) {
            refs.add(ds.preimage());
        } else if (value instanceof AddOutput ao) {
            refs.add(ao.satoshis());
            refs.addAll(ao.stateValues());
            if (ao.preimage() != null && !ao.preimage().isEmpty()) refs.add(ao.preimage());
        } else if (value instanceof AddRawOutput ar) {
            refs.add(ar.satoshis());
            refs.add(ar.scriptBytes());
        } else if (value instanceof AddDataOutput ad) {
            refs.add(ad.satoshis());
            refs.add(ad.scriptBytes());
        } else if (value instanceof ArrayLiteral al) {
            refs.addAll(al.elements());
        } else if (value instanceof RawScript) {
            // Opaque byte span — no SSA operand refs.
        } else {
            // Exhaustiveness guard. Refusing to handle unknown ANF kinds here
            // is critical: silently returning [] would make last-use / liveness
            // analysis produce wrong PICK/ROLL placement and corrupt Stack IR.
            throw new UnknownAnfKindError(value.kind(), "stack-lower.collectRefs");
        }
        return refs;
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    public static StackProgram run(AnfProgram program) {
        Map<String, AnfMethod> privateMethods = new HashMap<>();
        for (AnfMethod m : program.methods()) {
            if (!m.isPublic() && !"constructor".equals(m.name())) {
                privateMethods.put(m.name(), m);
            }
        }

        List<StackMethod> out = new ArrayList<>();
        for (AnfMethod m : program.methods()) {
            if ("constructor".equals(m.name()) || !m.isPublic()) continue;
            out.add(lowerMethod(m, program.properties(), privateMethods));
        }

        return new StackProgram(program.contractName(), out);
    }

    private static StackMethod lowerMethod(
        AnfMethod method,
        List<AnfProperty> properties,
        Map<String, AnfMethod> privateMethods
    ) {
        List<String> paramNames = new ArrayList<>();
        for (AnfParam p : method.params()) paramNames.add(p.name());

        if (methodUsesCheckPreimage(method.body(), privateMethods, new java.util.HashSet<>())) {
            // Implicit param pushed by the SDK before the developer's params.
            // Order matches the Python / Go / Rust references exactly:
            // the final paramNames layout is [_codePart, ...declared params...].
            //
            // BUG-100 fix: the OP_PUSH_TX signature is now derived on-chain from
            // the preimage (see lowerCheckPreimage), so NO _opPushTxSig witness
            // item is pushed. The unlocking script provides only the preimage.
            //
            // _codePart is provisioned for continuation builders
            // (add_output/add_raw_output/computeStateOutput) OR when the method
            // reads a mutable variable-length (ByteString) state field — the
            // var-length deserialization needs it for the preimage-relative
            // offset (issue #100).
            java.util.Set<String> varLenProps = new java.util.HashSet<>();
            for (AnfProperty p : properties) {
                if (!p.readonly() && "ByteString".equals(p.type())) varLenProps.add(p.name());
            }
            if (methodUsesCodePart(method.body())
                || methodReadsVarLenState(method.body(), varLenProps, privateMethods, new java.util.HashSet<>())) {
                paramNames.add(0, "_codePart");
            }
        }

        LoweringContext ctx = new LoweringContext(paramNames, properties, privateMethods);
        ctx.lowerBindings(method.body(), method.isPublic());

        // Strip excess stack items below the top-of-stack boolean (CLEANSTACK).
        // Excess items can come from deserialize_state (stateful methods reading
        // mutable fields) or from readonly-field-binding patterns in all-readonly
        // terminal methods. The depth() > 1 guard keeps this a no-op for
        // already-clean methods.
        if (method.isPublic() && ctx.sm.depth() > 1) {
            int excess = ctx.sm.depth() - 1;
            for (int i = 0; i < excess; i++) {
                ctx.emitOp(new NipOp());
                ctx.sm.removeAtDepth(1);
            }
        }

        if (ctx.maxDepth > MAX_STACK_DEPTH) {
            throw new RuntimeException("method '" + method.name()
                + "' exceeds maximum stack depth of " + MAX_STACK_DEPTH
                + " (actual: " + ctx.maxDepth + ")");
        }

        return new StackMethod(method.name(), ctx.ops, ctx.maxDepth);
    }

    /**
     * Recursively check whether {@code body} (and any private methods it
     * calls, transitively) contains a CheckPreimage. 2026-04-30 audit
     * finding F7: previous shallow scan missed manual checkPreimage
     * calls inside if/loop bodies and private helpers, causing stack
     * lowering to fail with `Value '_opPushTxSig' not found on stack`.
     */
    private static boolean methodUsesCheckPreimage(
            List<AnfBinding> body,
            Map<String, AnfMethod> privateMethods,
            java.util.Set<String> seen) {
        for (AnfBinding b : body) {
            AnfValue v = b.value();
            if (v instanceof CheckPreimage) return true;
            if (v instanceof If iv) {
                if (methodUsesCheckPreimage(iv.thenBranch(), privateMethods, seen)) return true;
                if (methodUsesCheckPreimage(iv.elseBranch(), privateMethods, seen)) return true;
            }
            if (v instanceof Loop loop) {
                if (methodUsesCheckPreimage(loop.body(), privateMethods, seen)) return true;
            }
            if (v instanceof MethodCall mc && privateMethods != null) {
                AnfMethod target = privateMethods.get(mc.method());
                if (target != null && !seen.contains(target.name())) {
                    java.util.Set<String> nextSeen = new java.util.HashSet<>(seen);
                    nextSeen.add(target.name());
                    if (methodUsesCheckPreimage(target.body(), privateMethods, nextSeen)) return true;
                }
            }
        }
        return false;
    }

    private static boolean methodUsesCodePart(List<AnfBinding> body) {
        for (AnfBinding b : body) {
            AnfValue v = b.value();
            if (v instanceof AddOutput || v instanceof AddRawOutput || v instanceof AddDataOutput) return true;
            if (v instanceof Call c && ("computeStateOutput".equals(c.func()) || "computeStateOutputHash".equals(c.func()))) {
                return true;
            }
            if (v instanceof If iv) {
                if (methodUsesCodePart(iv.thenBranch()) || methodUsesCodePart(iv.elseBranch())) return true;
            }
            if (v instanceof Loop l && methodUsesCodePart(l.body())) return true;
        }
        return false;
    }

    /**
     * Issue #100: a terminal method that READS a mutable variable-length
     * (ByteString) state field needs {@code _codePart} on the stack so the
     * preimage-relative var-length deserialization can compute the state
     * offset. Narrowed to a live {@code load_prop} of a non-readonly ByteString
     * property: methods that only read readonly fields (baked into the locking
     * script) or fixed-size fields keep their original terminal codegen.
     *
     * <p>Deep-review finding C18: private methods are INLINED into the caller's
     * stack context, so the scan must recurse through private {@code method_call}
     * targets exactly like the sibling {@link #methodUsesCheckPreimage} does.
     * Without it a public method whose only read of a mutable ByteString field
     * happens inside a private helper never gets {@code _codePart}, the
     * var-length deserialization is skipped, and the {@code load_prop} silently
     * falls back to the deploy-time constant instead of the live state.
     */
    private static boolean methodReadsVarLenState(
            List<AnfBinding> body,
            java.util.Set<String> varLenProps,
            Map<String, AnfMethod> privateMethods,
            java.util.Set<String> seen) {
        for (AnfBinding b : body) {
            AnfValue v = b.value();
            if (v instanceof LoadProp lp && varLenProps.contains(lp.name())) return true;
            if (v instanceof If iv) {
                if (methodReadsVarLenState(iv.thenBranch(), varLenProps, privateMethods, seen)
                    || methodReadsVarLenState(iv.elseBranch(), varLenProps, privateMethods, seen)) return true;
            }
            if (v instanceof Loop l
                && methodReadsVarLenState(l.body(), varLenProps, privateMethods, seen)) return true;
            if (v instanceof MethodCall mc && privateMethods != null) {
                AnfMethod target = privateMethods.get(mc.method());
                if (target != null && !seen.contains(target.name())) {
                    java.util.Set<String> nextSeen = new java.util.HashSet<>(seen);
                    nextSeen.add(target.name());
                    if (methodReadsVarLenState(target.body(), varLenProps, privateMethods, nextSeen)) return true;
                }
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // LoweringContext
    // ------------------------------------------------------------------

    static final class LoweringContext {
        final StackMap sm;
        final List<StackOp> ops = new ArrayList<>();
        int maxDepth;
        final List<AnfProperty> properties;
        Map<String, AnfMethod> privateMethods = new HashMap<>();
        Map<String, Boolean> localBindings = new HashMap<>();
        Set<String> outerProtectedRefs;
        boolean insideBranch;
        /**
         * Method params whose names collide with a MUTABLE property. Maps the
         * param name to the reserved stack-slot name its witness value lives
         * under, so {@code lowerLoadParam} reads the param and not the
         * same-named deserialized property slot (issue #130). Empty for the
         * common no-collision case (byte-identical output).
         */
        Map<String, String> renamedParams = new HashMap<>();
        // Element counts for array_literal bindings (used by checkMultiSig).
        Map<String, Integer> arrayLengths = new HashMap<>();
        // Element refs for array_literal bindings (used by checkMultiSig).
        Map<String, List<String>> arrayElements = new HashMap<>();
        // GAP-002: current AnfBinding's sourceLoc, threaded onto every
        // StackOp emitted while that binding lowers. The Emit pass walks
        // op.sourceLoc() to build the artifact's sourceMap.
        runar.compiler.ir.ast.SourceLocation currentSourceLoc;

        LoweringContext(List<String> params, List<AnfProperty> properties) {
            this.sm = new StackMap(params);
            this.properties = properties;

            // Issue #130 (stack layer): a method param whose name collides with
            // a MUTABLE property gets a duplicate stackMap slot once
            // `deserialize_state` pushes that property under the same name. Name
            // lookups resolve to the shallowest match (the deserialized
            // property), so `load_param` would read the stale on-chain state
            // instead of the witness value. Rename the colliding param's slot to
            // a reserved, collision-proof name up front and remember the mapping
            // so `lowerLoadParam` targets the real param slot. Only mutable
            // properties are deserialized onto the stack, so readonly shadows
            // (handled purely by ANF resolution) never enter this map, and
            // non-colliding contracts get an empty map — byte-identical output.
            if (params != null && properties != null) {
                Set<String> mutablePropNames = new java.util.HashSet<>();
                for (AnfProperty p : properties) {
                    if (!p.readonly()) mutablePropNames.add(p.name());
                }
                for (String name : params) {
                    if (name != null && mutablePropNames.contains(name)) {
                        String renamed = "__param_" + name;
                        sm.renameAtDepth(sm.findDepth(name), renamed);
                        renamedParams.put(name, renamed);
                    }
                }
            }

            trackDepth();
        }

        LoweringContext(List<String> params, List<AnfProperty> properties, Map<String, AnfMethod> privateMethods) {
            this(params, properties);
            this.privateMethods = privateMethods;
        }

        void trackDepth() {
            if (sm.depth() > maxDepth) maxDepth = sm.depth();
        }

        void emitOp(StackOp op) {
            // GAP-002: re-stamp the op with the current source loc so the
            // Emit pass can read it back. Only re-stamp ops that don't
            // already carry one (e.g. those produced by upstream passes
            // before this LoweringContext was active).
            ops.add(stampSourceLoc(op, currentSourceLoc));
            trackDepth();
        }

        private static runar.compiler.ir.stack.StackOp stampSourceLoc(
            runar.compiler.ir.stack.StackOp op,
            runar.compiler.ir.ast.SourceLocation loc
        ) {
            if (loc == null) return op;
            runar.compiler.ir.stack.StackSourceLoc sl =
                new runar.compiler.ir.stack.StackSourceLoc(loc.file(), loc.line(), loc.column());
            if (op instanceof runar.compiler.ir.stack.OpcodeOp o) {
                if (o.sourceLoc() != null) return o;
                return new runar.compiler.ir.stack.OpcodeOp(o.code(), sl);
            }
            if (op instanceof runar.compiler.ir.stack.DupOp d) {
                if (d.sourceLoc() != null) return d;
                return new runar.compiler.ir.stack.DupOp(sl);
            }
            if (op instanceof runar.compiler.ir.stack.SwapOp d) {
                if (d.sourceLoc() != null) return d;
                return new runar.compiler.ir.stack.SwapOp(sl);
            }
            if (op instanceof runar.compiler.ir.stack.DropOp d) {
                if (d.sourceLoc() != null) return d;
                return new runar.compiler.ir.stack.DropOp(sl);
            }
            if (op instanceof runar.compiler.ir.stack.NipOp d) {
                if (d.sourceLoc() != null) return d;
                return new runar.compiler.ir.stack.NipOp(sl);
            }
            if (op instanceof runar.compiler.ir.stack.OverOp d) {
                if (d.sourceLoc() != null) return d;
                return new runar.compiler.ir.stack.OverOp(sl);
            }
            if (op instanceof runar.compiler.ir.stack.RotOp d) {
                if (d.sourceLoc() != null) return d;
                return new runar.compiler.ir.stack.RotOp(sl);
            }
            if (op instanceof runar.compiler.ir.stack.TuckOp d) {
                if (d.sourceLoc() != null) return d;
                return new runar.compiler.ir.stack.TuckOp(sl);
            }
            if (op instanceof runar.compiler.ir.stack.PushOp p) {
                if (p.sourceLoc() != null) return p;
                return new runar.compiler.ir.stack.PushOp(p.value(), sl);
            }
            if (op instanceof runar.compiler.ir.stack.PickOp p) {
                if (p.sourceLoc() != null) return p;
                return new runar.compiler.ir.stack.PickOp(p.depth(), sl);
            }
            if (op instanceof runar.compiler.ir.stack.RollOp p) {
                if (p.sourceLoc() != null) return p;
                return new runar.compiler.ir.stack.RollOp(p.depth(), sl);
            }
            if (op instanceof runar.compiler.ir.stack.IfOp i) {
                if (i.sourceLoc() != null) return i;
                return new runar.compiler.ir.stack.IfOp(i.thenBranch(), i.elseBranch(), sl);
            }
            if (op instanceof runar.compiler.ir.stack.PlaceholderOp p) {
                if (p.sourceLoc() != null) return p;
                return new runar.compiler.ir.stack.PlaceholderOp(p.paramIndex(), p.paramName(), sl);
            }
            if (op instanceof runar.compiler.ir.stack.PushCodeSepIndexOp p) {
                if (p.sourceLoc() != null) return p;
                return new runar.compiler.ir.stack.PushCodeSepIndexOp(sl);
            }
            // RawBytesOp has no sourceLoc field — skip.
            return op;
        }

        LoweringContext subContext() {
            LoweringContext c = new LoweringContext(null, properties);
            c.sm.slots.addAll(this.sm.slots);
            c.privateMethods = this.privateMethods;
            // Issue #130: a `load_param` for a shadowed param inside a branch
            // body must resolve to the same reserved renamed slot the parent set
            // up (the parent copied its renamed slot names into c.sm above).
            c.renamedParams = this.renamedParams;
            // GAP-002: nested branches keep the outer statement's loc by
            // default; the inner binding loop will override on each step.
            c.currentSourceLoc = this.currentSourceLoc;
            return c;
        }

        // ---------------- bring_to_top ----------------

        void bringToTop(String name, boolean consume) {
            int depth = sm.findDepth(name);
            if (depth < 0) throw new RuntimeException("value '" + name + "' not found on stack");

            if (depth == 0) {
                if (!consume) {
                    emitOp(new DupOp());
                    sm.dup();
                }
                return;
            }

            if (depth == 1 && consume) {
                emitOp(new SwapOp());
                sm.swap();
                return;
            }

            if (consume) {
                if (depth == 2) {
                    emitOp(new RotOp());
                    String removed = sm.removeAtDepth(2);
                    sm.push(removed);
                } else {
                    emitOp(new PushOp(PushValue.of(depth)));
                    sm.push("");
                    emitOp(new RollOp(depth));
                    sm.pop();
                    String rolled = sm.removeAtDepth(depth);
                    sm.push(rolled);
                }
            } else {
                if (depth == 1) {
                    emitOp(new OverOp());
                    String picked = sm.peekAtDepth(1);
                    sm.push(picked);
                } else {
                    emitOp(new PushOp(PushValue.of(depth)));
                    sm.push("");
                    emitOp(new PickOp(depth));
                    sm.pop();
                    String picked = sm.peekAtDepth(depth);
                    sm.push(picked);
                }
            }
            trackDepth();
        }

        /**
         * Drain branch-private residue from below TOS at the end of a branch
         * body, so both branches converge to a layout the parent stack model
         * can faithfully describe before OP_ENDIF (issue #36).
         *
         * A slot is residue when its name is NOT in {@code preIfNames} (the
         * snapshot of the parent's named slots taken before the branch ran).
         * This catches both anonymous slots (empty-named, pushed by intrinsics
         * like substr's OP_SPLIT residue) and named branch-local bindings that
         * lingered past their last-use (e.g. dead-code load_const intermediates
         * the optimizer didn't fold). Slots whose name was already in
         * {@code preIfNames} are kept. Process deepest-first so removing a
         * deeper slot doesn't shift a shallower slot's depth-from-top.
         */
        /** Physically remove the stack slot {@code depth} places below the top. */
        void dropSlotAtDepth(int depth) {
            if (depth == 0) {
                emitOp(new DropOp());
                sm.pop();
                return;
            }
            if (depth == 1) {
                emitOp(new NipOp());
                sm.removeAtDepth(1);
                return;
            }
            emitOp(new PushOp(PushValue.of(depth)));
            sm.push("");
            emitOp(new RollOp(depth));
            sm.pop();
            String rolled = sm.removeAtDepth(depth);
            sm.push(rolled);
            emitOp(new DropOp());
            sm.pop();
        }

        void drainBranchPrivateResidue(Set<String> preIfNames) {
            List<Integer> drainDepths = new ArrayList<>();
            for (int d = 1; d < sm.depth(); d++) {
                String name = sm.peekAtDepth(d);
                if (name == null || name.isEmpty()) {
                    drainDepths.add(d);
                } else if (!preIfNames.contains(name)) {
                    drainDepths.add(d);
                }
            }
            if (drainDepths.isEmpty()) return;
            drainDepths.sort((a, b) -> b - a);
            for (int depth : drainDepths) {
                if (depth == 1) {
                    emitOp(new NipOp());
                    sm.removeAtDepth(1);
                } else {
                    emitOp(new PushOp(PushValue.of(depth)));
                    sm.push("");
                    emitOp(new RollOp(depth));
                    sm.pop();
                    String rolled = sm.removeAtDepth(depth);
                    sm.push(rolled);
                    emitOp(new DropOp());
                    sm.pop();
                }
            }
        }

        boolean isLastUse(String ref, int currentIndex, Map<String, Integer> lastUses) {
            Integer last = lastUses.get(ref);
            if (last == null) return true;
            return last <= currentIndex;
        }

        /**
         * Consume-vs-copy decision for one operand of a multi-operand ANF value.
         *
         * <p>{@code operands} is the FULL operand-ref list of the value (including
         * {@code ref} itself). The load may consume (ROLL / move) the ref only when
         * this binding is the ref's last use AND the ref occurs exactly once in the
         * operand list. A ref read at more than one operand position of the same
         * value must be copied (PICK / DUP) at EVERY position: a consume-mode
         * bringToTop of a ref already on top of the stack is a no-op, so two
         * consume-mode loads of the same ref would leave a single slot for an opcode
         * that pops one item per operand (e.g. {@code t := x + x} underflowing
         * OP_ADD), or silently pair the opcode with the wrong slot. The original then
         * stays on the stack and the existing method epilogue cleans it up.
         * Unreachable from the frontend (every operand gets a fresh temp); reachable
         * via AnfLoader / CLI --ir hand-written ANF.
         */
        boolean operandConsume(String ref, List<String> operands, int currentIndex,
                               Map<String, Integer> lastUses) {
            if (!isLastUse(ref, currentIndex, lastUses)) return false;
            int occurrences = 0;
            for (String o : operands) {
                if (o.equals(ref)) occurrences++;
            }
            return occurrences <= 1;
        }

        // ---------------- lower_bindings ----------------

        void lowerBindings(List<AnfBinding> bindings, boolean terminalAssert) {
            localBindings = new HashMap<>();
            for (AnfBinding b : bindings) localBindings.put(b.name(), true);

            Map<String, Integer> lastUses = computeLastUses(bindings);

            if (outerProtectedRefs != null) {
                for (String ref : outerProtectedRefs) {
                    lastUses.put(ref, bindings.size());
                }
            }

            int lastAssertIdx = -1;
            int terminalIfIdx = -1;
            if (terminalAssert && !bindings.isEmpty()) {
                AnfBinding last = bindings.get(bindings.size() - 1);
                if (last.value() instanceof If) {
                    terminalIfIdx = bindings.size() - 1;
                } else {
                    for (int i = bindings.size() - 1; i >= 0; i--) {
                        if (bindings.get(i).value() instanceof Assert) {
                            lastAssertIdx = i;
                            break;
                        }
                    }
                }
            }

            for (int i = 0; i < bindings.size(); i++) {
                AnfBinding b = bindings.get(i);
                // GAP-002: stamp the binding's sourceLoc onto every StackOp
                // emitted while it lowers. We deliberately keep the loc
                // sticky AFTER the binding closes — nothing reads it until
                // the next binding overwrites it — so peephole-survivable
                // ops get a deterministic anchor.
                runar.compiler.ir.ast.SourceLocation prev = currentSourceLoc;
                if (b.sourceLoc() != null) {
                    currentSourceLoc = b.sourceLoc();
                }
                try {
                    if (b.value() instanceof Assert a && i == lastAssertIdx) {
                        lowerAssert(a.value(), i, lastUses, true);
                    } else if (b.value() instanceof If iv && i == terminalIfIdx) {
                        lowerIf(b.name(), iv.cond(), iv.thenBranch(), iv.elseBranch(),
                            iv.results() == null ? List.of() : iv.results(), i, lastUses, true);
                    } else {
                        lowerBinding(b, i, lastUses);
                    }
                } finally {
                    currentSourceLoc = prev;
                }
            }
        }

        // ---------------- lower_binding dispatch ----------------

        void lowerBinding(AnfBinding b, int idx, Map<String, Integer> lastUses) {
            String name = b.name();
            AnfValue v = b.value();

            if (v instanceof LoadParam lp) {
                lowerLoadParam(name, lp.name(), idx, lastUses);
            } else if (v instanceof LoadProp p) {
                lowerLoadProp(name, p.name());
            } else if (v instanceof LoadConst lc) {
                lowerLoadConst(name, lc, idx, lastUses);
            } else if (v instanceof BinOp bo) {
                lowerBinOp(name, bo.op(), bo.left(), bo.right(), idx, lastUses, bo.resultType());
            } else if (v instanceof UnaryOp uo) {
                lowerUnaryOp(name, uo.op(), uo.operand(), idx, lastUses);
            } else if (v instanceof Call c) {
                lowerCall(name, c.func(), c.args(), idx, lastUses);
            } else if (v instanceof MethodCall mc) {
                lowerMethodCall(name, mc.object(), mc.method(), mc.args(), idx, lastUses);
            } else if (v instanceof If iv) {
                lowerIf(name, iv.cond(), iv.thenBranch(), iv.elseBranch(),
                    iv.results() == null ? List.of() : iv.results(), idx, lastUses, false);
            } else if (v instanceof Loop l) {
                lowerLoop(name, l.count(), l.body(), l.iterVar(), l.start(), l.step(), idx, lastUses);
            } else if (v instanceof Assert a) {
                lowerAssert(a.value(), idx, lastUses, false);
            } else if (v instanceof UpdateProp up) {
                lowerUpdateProp(up.name(), up.value(), idx, lastUses);
            } else if (v instanceof GetStateScript) {
                lowerGetStateScript(name);
            } else if (v instanceof CheckPreimage cp) {
                lowerCheckPreimage(name, cp.preimage(), cp.sighashFlag(), idx, lastUses);
            } else if (v instanceof DeserializeState ds) {
                lowerDeserializeState(ds.preimage(), idx, lastUses);
            } else if (v instanceof AddOutput ao) {
                lowerAddOutput(name, ao.satoshis(), ao.stateValues(), ao.preimage(), idx, lastUses);
            } else if (v instanceof AddRawOutput ar) {
                lowerAddRawOutput(name, ar.satoshis(), ar.scriptBytes(), idx, lastUses);
            } else if (v instanceof AddDataOutput ad) {
                // wire shape matches add_raw_output
                lowerAddRawOutput(name, ad.satoshis(), ad.scriptBytes(), idx, lastUses);
            } else if (v instanceof ArrayLiteral al) {
                lowerArrayLiteral(name, al.elements(), idx, lastUses);
            } else if (v instanceof RawScript rs) {
                lowerRawScript(name, rs.bytes(), rs.inArity(), rs.outArity());
            } else {
                // Exhaustiveness guard. Silently skipping an unknown ANF kind
                // here would emit a script that omits the binding entirely —
                // passing type-check while producing wrong on-chain bytes.
                throw new UnknownAnfKindError(v.kind(), "stack-lower.lowerBinding");
            }
        }

        // ---------------- load_param / load_prop / load_const ----------------

        void lowerLoadParam(String bindingName, String paramName, int idx, Map<String, Integer> lastUses) {
            // The parameter is already on the stack under its original name — or,
            // for a param that shadows a mutable property, under a reserved
            // renamed slot (issue #130) so it is not confused with the
            // deserialized property slot.
            String slotName = renamedParams.getOrDefault(paramName, paramName);
            if (sm.has(slotName)) {
                boolean isLast = isLastUse(paramName, idx, lastUses);
                bringToTop(slotName, isLast);
                sm.pop();
                sm.push(bindingName);
            } else {
                // Parameter no longer on the stack — a compiler invariant
                // violation (historically caused by unrolled loops consuming
                // outer refs; see lowerLoop). Silently emitting OP_0 here
                // produced scripts that compiled, passed the env-based
                // interpreter, and then failed on chain — fail loudly instead.
                throw new RuntimeException(
                    "Stack lowering: method parameter '" + paramName + "' is not on the stack "
                        + "at a post-consumption reference (stack: [" + sm.debugSlots() + "]). "
                        + "Refusing to emit a silent OP_0 placeholder.");
            }
        }

        void lowerLoadProp(String bindingName, String propName) {
            AnfProperty prop = null;
            for (AnfProperty p : properties) {
                if (p.name().equals(propName)) { prop = p; break; }
            }

            if (sm.has(propName)) {
                bringToTop(propName, false);
                sm.pop();
            } else if (prop != null && prop.initialValue() != null) {
                pushPropertyValue(prop.initialValue());
            } else {
                // Deployment-time constructor arg placeholder.
                //
                // #119 tail (H1): a property that reaches this fallback with no
                // matching constructor slot (paramIndex < 0) has no deploy-time
                // bytes of its own. The previous behaviour coerced it onto slot
                // 0, silently splicing an UNRELATED constructor argument's
                // placeholder into the locking script — a silent-wrong-code
                // path. Fail loudly instead. (A real constructor-param property
                // — readonly, or a mutable state field whose initial value is
                // spliced at deploy — is found and unaffected, so zero golden
                // churn.)
                List<String> ctorProps = new ArrayList<>();
                for (AnfProperty p : properties) {
                    if (p.initialValue() != null) continue;
                    ctorProps.add(p.name());
                }
                int paramIndex = ctorProps.indexOf(propName);
                if (paramIndex < 0) {
                    String loc = currentSourceLoc != null
                        ? " at " + currentSourceLoc.file() + ":" + currentSourceLoc.line()
                            + ":" + currentSourceLoc.column()
                        : "";
                    throw new RuntimeException(
                        "Stack lowering: property '" + propName + "'" + loc
                            + " is neither on the stack, initialized, nor a constructor "
                            + "parameter, so it has no deploy-time slot. Refusing to emit "
                            + "a placeholder for an unrelated constructor argument (slot 0). "
                            + "Known constructor-param properties: ["
                            + String.join(", ", ctorProps) + "].");
                }
                emitOp(new PlaceholderOp(paramIndex, propName));
            }
            sm.push(bindingName);
        }

        void pushPropertyValue(ConstValue v) {
            if (v instanceof BoolConst b) {
                emitOp(new PushOp(PushValue.of(b.value())));
            } else if (v instanceof BigIntConst i) {
                emitOp(new PushOp(PushValue.of(i.value())));
            } else if (v instanceof BytesConst bs) {
                emitOp(new PushOp(PushValue.ofHex(bs.hex())));
            } else {
                emitOp(new PushOp(PushValue.of(0)));
            }
        }

        void lowerLoadConst(String bindingName, LoadConst lc, int idx, Map<String, Integer> lastUses) {
            ConstValue cv = lc.value();
            if (cv instanceof BytesConst bc) {
                String raw = bc.hex();
                if (raw != null && raw.length() > 5 && raw.startsWith("@ref:")) {
                    String refName = raw.substring(5);
                    // Special case: aliasing an array_literal (metadata-only
                    // binding, not present in the stack-map). Copy the array
                    // metadata under the new binding name and emit no stack moves.
                    List<String> refElems = arrayElements.get(refName);
                    if (refElems != null) {
                        arrayElements.put(bindingName, new ArrayList<>(refElems));
                        Integer refLen = arrayLengths.get(refName);
                        if (refLen != null) arrayLengths.put(bindingName, refLen);
                        return;
                    }
                    if (sm.has(refName)) {
                        boolean consume = Boolean.TRUE.equals(localBindings.get(refName))
                            && isLastUse(refName, idx, lastUses);
                        bringToTop(refName, consume);
                        sm.pop();
                        sm.push(bindingName);
                    } else {
                        // Referenced value no longer on the stack — a compiler
                        // invariant violation (see lowerLoadParam for the
                        // loop-consumption history). Fail loudly instead of
                        // silently emitting OP_0.
                        throw new RuntimeException(
                            "Stack lowering: value '" + refName + "' referenced by '" + bindingName
                                + "' is not on the stack (stack: [" + sm.debugSlots() + "]). "
                                + "Refusing to emit a silent OP_0 placeholder.");
                    }
                    return;
                }
                if ("@this".equals(raw)) {
                    emitOp(new PushOp(PushValue.of(0)));
                    sm.push(bindingName);
                    return;
                }
                emitOp(new PushOp(PushValue.ofHex(raw)));
                sm.push(bindingName);
            } else if (cv instanceof BoolConst b) {
                emitOp(new PushOp(PushValue.of(b.value())));
                sm.push(bindingName);
            } else if (cv instanceof BigIntConst i) {
                emitOp(new PushOp(PushValue.of(i.value())));
                sm.push(bindingName);
            } else {
                emitOp(new PushOp(PushValue.of(0)));
                sm.push(bindingName);
            }
        }

        // ---------------- bin_op / unary_op ----------------

        void lowerBinOp(String bindingName, String op, String left, String right,
                        int idx, Map<String, Integer> lastUses, String resultType) {
            List<String> binOperands = List.of(left, right);
            bringToTop(left, operandConsume(left, binOperands, idx, lastUses));
            bringToTop(right, operandConsume(right, binOperands, idx, lastUses));
            sm.pop();
            sm.pop();

            if ("bytes".equals(resultType) && ("===".equals(op) || "!==".equals(op))) {
                emitOp(new OpcodeOp("OP_EQUAL"));
                if ("!==".equals(op)) emitOp(new OpcodeOp("OP_NOT"));
            } else if ("bytes".equals(resultType) && "+".equals(op)) {
                emitOp(new OpcodeOp("OP_CAT"));
            } else {
                List<String> opcodes = BINOP_OPCODES.get(op);
                if (opcodes == null) throw new RuntimeException("unknown binary operator: " + op);
                for (String c : opcodes) emitOp(new OpcodeOp(c));
            }

            sm.push(bindingName);
            trackDepth();
        }

        void lowerUnaryOp(String bindingName, String op, String operand, int idx, Map<String, Integer> lastUses) {
            bringToTop(operand, isLastUse(operand, idx, lastUses));
            sm.pop();

            List<String> opcodes = UNARYOP_OPCODES.get(op);
            if (opcodes == null) throw new RuntimeException("unknown unary operator: " + op);
            for (String c : opcodes) emitOp(new OpcodeOp(c));

            sm.push(bindingName);
            trackDepth();
        }

        // ---------------- call ----------------

        void lowerCall(String bindingName, String funcName, List<String> args,
                       int idx, Map<String, Integer> lastUses) {
            if ("assert".equals(funcName) || "exit".equals(funcName)) {
                if (!args.isEmpty()) {
                    bringToTop(args.get(0), isLastUse(args.get(0), idx, lastUses));
                    sm.pop();
                    emitOp(new OpcodeOp("OP_VERIFY"));
                    sm.push(bindingName);
                }
                return;
            }
            if ("super".equals(funcName)) {
                sm.push(bindingName);
                return;
            }
            if ("checkMultiSig".equals(funcName) && args.size() == 2) {
                lowerCheckMultiSig(bindingName, args, idx, lastUses);
                return;
            }
            if ("pack".equals(funcName) || "toByteString".equals(funcName)) {
                if (!args.isEmpty()) {
                    String arg = args.get(0);
                    bringToTop(arg, isLastUse(arg, idx, lastUses));
                    sm.pop();
                    sm.push(bindingName);
                }
                return;
            }
            if ("buildChangeOutput".equals(funcName)) {
                lowerBuildChangeOutput(bindingName, args, idx, lastUses);
                return;
            }
            if ("computeStateOutput".equals(funcName)) {
                lowerComputeStateOutput(bindingName, args, idx, lastUses);
                return;
            }
            if ("computeStateOutputHash".equals(funcName)) {
                lowerComputeStateOutputHash(bindingName, args, idx, lastUses);
                return;
            }
            if ("extractOutputHash".equals(funcName)) {
                lowerExtractOutputHash(bindingName, args, idx, lastUses);
                return;
            }
            if (funcName.length() > 7 && funcName.startsWith("extract")) {
                lowerExtractor(bindingName, funcName, args, idx, lastUses);
                return;
            }

            // ------------------------------------------------------------------
            // M6: crypto builtins -- dispatch to dedicated codegen modules.
            // Each module emits a long, self-contained op sequence that leaves
            // a single named result on the stack.
            // ------------------------------------------------------------------
            if ("sha256Compress".equals(funcName)) {
                lowerSha256Compress(bindingName, args, idx, lastUses);
                return;
            }
            if ("sha256Finalize".equals(funcName)) {
                lowerSha256Finalize(bindingName, args, idx, lastUses);
                return;
            }
            if (runar.compiler.codegen.Ec.isEcBuiltin(funcName)) {
                lowerEcBuiltin(bindingName, funcName, args, idx, lastUses);
                return;
            }
            if (runar.compiler.codegen.P256P384.isNistEcBuiltin(funcName)
                || runar.compiler.codegen.P256P384.isVerifyEcdsaBuiltin(funcName)) {
                lowerNistEcBuiltin(bindingName, funcName, args, idx, lastUses);
                return;
            }
            if (runar.compiler.codegen.Blake3.isBlake3Builtin(funcName)) {
                lowerBlake3Builtin(bindingName, funcName, args, idx, lastUses);
                return;
            }
            if (runar.compiler.codegen.SlhDsa.isSlhDsaBuiltin(funcName)) {
                lowerVerifySlhDsa(bindingName, funcName, args, idx, lastUses);
                return;
            }
            if (runar.compiler.codegen.Wots.isWotsBuiltin(funcName)) {
                lowerWotsBuiltin(bindingName, funcName, args, idx, lastUses);
                return;
            }
            if (runar.compiler.codegen.Rabin.isRabinBuiltin(funcName)) {
                lowerRabinBuiltin(bindingName, funcName, args, idx, lastUses);
                return;
            }

            // ------------------------------------------------------------------
            // Go-only Mode-3 STARK / FRI / Groth16 verifier families:
            // BabyBear, KoalaBear, Poseidon2-KB, Poseidon2-Merkle, BN254/Groth16,
            // sha256-Merkle, FiatShamir-KB. Java tier carries presence-only stubs
            // for parity with the other 5 non-Go tiers; the dispatch methods
            // throw UnsupportedOperationException with a CLAUDE.md pointer.
            // Fixtures that exercise these primitives MUST carry a
            // "compilers": ["go"] allowlist in source.json. See CLAUDE.md
            // ("Go-only crypto codegen modules") and conformance/README.md.
            // ------------------------------------------------------------------
            if (runar.compiler.codegen.BabyBear.isBabyBearBuiltin(funcName)) {
                runar.compiler.codegen.BabyBear.dispatch(funcName, this::emitOp);
                return; // unreachable — dispatch always throws
            }
            if (runar.compiler.codegen.KoalaBear.isKoalaBearBuiltin(funcName)) {
                runar.compiler.codegen.KoalaBear.dispatch(funcName, this::emitOp);
                return; // unreachable
            }
            if (runar.compiler.codegen.Poseidon2KoalaBear.isPoseidon2KoalaBearBuiltin(funcName)) {
                runar.compiler.codegen.Poseidon2KoalaBear.dispatch(funcName, this::emitOp);
                return; // unreachable
            }
            if (runar.compiler.codegen.Poseidon2Merkle.isPoseidon2MerkleBuiltin(funcName)) {
                runar.compiler.codegen.Poseidon2Merkle.dispatch(funcName, this::emitOp);
                return; // unreachable
            }
            if (runar.compiler.codegen.Bn254.isBn254Builtin(funcName)) {
                runar.compiler.codegen.Bn254.dispatch(funcName, this::emitOp);
                return; // unreachable
            }
            if (runar.compiler.codegen.Merkle.isMerkleBuiltin(funcName)) {
                runar.compiler.codegen.Merkle.dispatch(funcName, this::emitOp);
                return; // unreachable
            }
            if (runar.compiler.codegen.FiatShamirKb.isFiatShamirKbBuiltin(funcName)) {
                runar.compiler.codegen.FiatShamirKb.dispatch(funcName, this::emitOp);
                return; // unreachable
            }

            // ------------------------------------------------------------------
            // Math + ByteString builtins: substr, safediv, safemod, percentOf.
            // Each emits a small fixed opcode sequence; mirror Python/Rust exactly.
            // ------------------------------------------------------------------
            if ("substr".equals(funcName)) {
                lowerSubstr(bindingName, args, idx, lastUses);
                return;
            }
            if ("safediv".equals(funcName) || "safemod".equals(funcName)) {
                lowerSafeDivMod(bindingName, funcName, args, idx, lastUses);
                return;
            }
            if ("percentOf".equals(funcName)) {
                lowerPercentOf(bindingName, args, idx, lastUses);
                return;
            }
            if ("clamp".equals(funcName)) {
                lowerClamp(bindingName, args, idx, lastUses);
                return;
            }
            if ("pow".equals(funcName)) {
                lowerPow(bindingName, args, idx, lastUses);
                return;
            }
            if ("mulDiv".equals(funcName)) {
                lowerMulDiv(bindingName, args, idx, lastUses);
                return;
            }
            if ("sqrt".equals(funcName)) {
                lowerSqrt(bindingName, args, idx, lastUses);
                return;
            }
            if ("gcd".equals(funcName)) {
                lowerGcd(bindingName, args, idx, lastUses);
                return;
            }
            if ("divmod".equals(funcName)) {
                lowerDivmod(bindingName, args, idx, lastUses);
                return;
            }
            if ("log2".equals(funcName)) {
                lowerLog2(bindingName, args, idx, lastUses);
                return;
            }
            if ("sign".equals(funcName)) {
                lowerSign(bindingName, args, idx, lastUses);
                return;
            }

            // General builtin path
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < args.size(); i++) sm.pop();

            List<String> opcodes = BUILTIN_OPCODES.get(funcName);
            if (opcodes == null) {
                // Go-only builtins are intercepted above via the BabyBear /
                // KoalaBear / Poseidon2KoalaBear / Poseidon2Merkle / Bn254 /
                // Merkle / FiatShamirKb dispatch chain, which throws
                // UnsupportedOperationException with a CLAUDE.md pointer.
                // Anything that reaches here is a genuinely unknown builtin.
                throw new IllegalStateException(
                    "unknown builtin: '" + funcName + "' is not a known Rúnar builtin. "
                    + "If this is a Rúnar built-in function, add it to StackLower.BUILTIN_OPCODES "
                    + "(or its dedicated lower* dispatch). If it is a user-defined helper, ensure it is "
                    + "declared as a private contract method so the inliner can resolve it.");
            }

            for (String c : opcodes) emitOp(new OpcodeOp(c));

            if ("split".equals(funcName)) {
                sm.push("");
                sm.push(bindingName);
            } else if ("len".equals(funcName)) {
                emitOp(new OpcodeOp("OP_NIP"));
                sm.push(bindingName);
            } else {
                sm.push(bindingName);
            }

            trackDepth();
        }

        // sha256Compress: [state, block] -> [newState]. See Sha256.emitSha256Compress.
        void lowerSha256Compress(String bindingName, List<String> args, int idx,
                                 Map<String, Integer> lastUses) {
            if (args.size() < 2) {
                throw new RuntimeException(
                    "sha256Compress requires 2 arguments: state, block");
            }
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < 2; i++) sm.pop();

            runar.compiler.codegen.Sha256.emitSha256Compress(this::emitOp);

            sm.push(bindingName);
            trackDepth();
        }

        // verifySLHDSA_SHA2_*: 3-arg crypto builtin that emits a multi-hundred-KB
        // verification script via the dedicated SLH-DSA codegen module.
        void lowerVerifySlhDsa(String bindingName, String funcName, List<String> args,
                               int idx, Map<String, Integer> lastUses) {
            if (args.size() < 3) {
                throw new RuntimeException(
                    "verifySLHDSA requires 3 arguments: msg, sig, pubkey");
            }
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < 3; i++) sm.pop();

            String paramKey = runar.compiler.codegen.SlhDsa.paramKey(funcName);
            runar.compiler.codegen.SlhDsa.emitVerifySlhDsa(this::emitOp, paramKey);

            sm.push(bindingName);
            trackDepth();
        }

        // EC builtins: delegate to Ec.dispatch for secp256k1 primitives.
        void lowerEcBuiltin(String bindingName, String funcName, List<String> args,
                            int idx, Map<String, Integer> lastUses) {
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < args.size(); i++) sm.pop();

            runar.compiler.codegen.Ec.dispatch(funcName, this::emitOp);

            sm.push(bindingName);
            trackDepth();
        }

        // NIST EC builtins (P-256, P-384, verifyECDSA_*): delegate to P256P384.dispatch.
        void lowerNistEcBuiltin(String bindingName, String funcName, List<String> args,
                                int idx, Map<String, Integer> lastUses) {
            if (runar.compiler.codegen.P256P384.isVerifyEcdsaBuiltin(funcName)
                && args.size() < 3) {
                throw new RuntimeException(
                    funcName + " requires 3 arguments: msg, sig, pubkey");
            }
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < args.size(); i++) sm.pop();

            runar.compiler.codegen.P256P384.dispatch(funcName, this::emitOp);

            sm.push(bindingName);
            trackDepth();
        }

        // BLAKE3 builtins: delegate to Blake3.dispatch.
        // blake3Compress: [chainingValue, block] -> [hash].
        // blake3Hash:     [message]              -> [hash].
        void lowerBlake3Builtin(String bindingName, String funcName, List<String> args,
                                int idx, Map<String, Integer> lastUses) {
            int expected = "blake3Compress".equals(funcName) ? 2 : 1;
            if (args.size() < expected) {
                throw new RuntimeException(
                    funcName + " requires " + expected + " argument" + (expected == 1 ? "" : "s"));
            }
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < args.size(); i++) sm.pop();

            runar.compiler.codegen.Blake3.dispatch(funcName, this::emitOp);

            sm.push(bindingName);
            trackDepth();
        }

        // verifyWOTS(msg, sig, pubkey) -> bool. Bring all three to the top in
        // call order, drop them off the stack model (the emit sequence consumes
        // them), let the codegen module emit the verifier opcodes, then push
        // the resulting bool under the binding name.
        void lowerWotsBuiltin(String bindingName, String funcName, List<String> args,
                              int idx, Map<String, Integer> lastUses) {
            if (args.size() < 3) {
                throw new RuntimeException(funcName + " requires 3 arguments: msg, sig, pubkey");
            }
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < args.size(); i++) sm.pop();

            runar.compiler.codegen.Wots.dispatch(funcName, this::emitOp);

            sm.push(bindingName);
            trackDepth();
        }

        // verifyRabinSig(msg, sig, padding, pubkey) -> bool.
        void lowerRabinBuiltin(String bindingName, String funcName, List<String> args,
                               int idx, Map<String, Integer> lastUses) {
            if (args.size() < 4) {
                throw new RuntimeException(
                    funcName + " requires 4 arguments: msg, sig, padding, pubkey");
            }
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < args.size(); i++) sm.pop();

            runar.compiler.codegen.Rabin.dispatch(funcName, this::emitOp);

            sm.push(bindingName);
            trackDepth();
        }

        // sha256Finalize: [state, remaining, msgBitLen] -> [hash].
        void lowerSha256Finalize(String bindingName, List<String> args, int idx,
                                 Map<String, Integer> lastUses) {
            if (args.size() < 3) {
                throw new RuntimeException(
                    "sha256Finalize requires 3 arguments: state, remaining, msgBitLen");
            }
            for (String a : args) {
                bringToTop(a, operandConsume(a, args, idx, lastUses));
            }
            for (int i = 0; i < 3; i++) sm.pop();

            runar.compiler.codegen.Sha256.emitSha256Finalize(this::emitOp);

            sm.push(bindingName);
            trackDepth();
        }

        // Lower checkMultiSig([sig1..sigN], [pk1..pkM]).
        //
        // OP_CHECKMULTISIG expects the stack (bottom -> top):
        //   <dummy=OP_0> <sig1> ... <sigN> <N> <pk1> ... <pkM> <M>
        //
        // args[0] and args[1] are bindings produced by array_literal. Those
        // bindings are NOT physical stack slots — their element refs live on
        // the stack-map as individual named bindings. We pull each element to
        // TOS via bringToTop. computeLastUses propagates each element's
        // last-use through the array indirection to THIS binding.
        void lowerCheckMultiSig(String bindingName, List<String> args, int idx, Map<String, Integer> lastUses) {
            String sigsRef = args.get(0);
            String pksRef = args.get(1);
            List<String> sigElems = arrayElements.get(sigsRef);
            List<String> pkElems = arrayElements.get(pksRef);
            if (sigElems == null || pkElems == null) {
                throw new RuntimeException(
                    "checkMultiSig: array_literal metadata missing (sigs=" + sigsRef + ", pks=" + pksRef + ")");
            }

            // Dummy OP_0 (historical CHECKMULTISIG off-by-one).
            emitOp(new PushOp(PushValue.of(0)));
            sm.push("");

            // A ref repeated across the combined element list (e.g. the same
            // pubkey twice) must be copied at every position — see operandConsume.
            List<String> msigOperands = new ArrayList<>(sigElems);
            msigOperands.addAll(pkElems);

            // Bring each sig element to TOS in declaration order.
            for (String sig : sigElems) {
                bringToTop(sig, operandConsume(sig, msigOperands, idx, lastUses));
            }

            // Push nSigs.
            emitOp(new PushOp(PushValue.of(sigElems.size())));
            sm.push("");

            // Bring each pubkey element to TOS in declaration order.
            for (String pk : pkElems) {
                bringToTop(pk, operandConsume(pk, msigOperands, idx, lastUses));
            }

            // Push nPKs.
            emitOp(new PushOp(PushValue.of(pkElems.size())));
            sm.push("");

            // OP_CHECKMULTISIG consumes: dummy + N sigs + nSigs + M pks + nPKs.
            int consumed = 1 + sigElems.size() + 1 + pkElems.size() + 1;
            for (int i = 0; i < consumed; i++) {
                sm.pop();
            }

            emitOp(new OpcodeOp("OP_CHECKMULTISIG"));
            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // substr(data, start, length): two OP_SPLIT passes with a NIP and a
        // DROP to extract the middle slice [start, start+length).
        // Mirrors compilers/python/runar_compiler/codegen/stack.py:_lower_substr
        // and compilers/rust/src/codegen/stack.rs::lower_substr.
        // Emitted opcodes (after stack is set up):
        //   OP_SPLIT OP_NIP OP_SPLIT OP_DROP
        // ------------------------------------------------------------------
        void lowerSubstr(String bindingName, List<String> args, int idx,
                         Map<String, Integer> lastUses) {
            if (args.size() < 3) {
                throw new RuntimeException("substr requires 3 arguments");
            }
            String data = args.get(0);
            String start = args.get(1);
            String length = args.get(2);

            bringToTop(data, operandConsume(data, args, idx, lastUses));
            bringToTop(start, operandConsume(start, args, idx, lastUses));

            // OP_SPLIT consumes [data, start] -> [left, right]
            sm.pop();
            sm.pop();
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.push(""); // left (will be discarded by NIP)
            sm.push(""); // right (kept)

            // NIP drops the left piece, leaving the right piece on top.
            emitOp(new NipOp());
            sm.pop();
            String rightPart = sm.pop();
            sm.push(rightPart);

            bringToTop(length, operandConsume(length, args, idx, lastUses));

            // OP_SPLIT consumes [right, length] -> [result, remainder]
            sm.pop();
            sm.pop();
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.push(""); // result (kept)
            sm.push(""); // remainder (will be dropped)

            // DROP the remainder.
            emitOp(new DropOp());
            sm.pop();
            sm.pop();

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // safediv(a, b) / safemod(a, b): a / b (or a % b) with a runtime
        // division-by-zero guard. Emits OP_DUP OP_0NOTEQUAL OP_VERIFY
        // followed by OP_DIV (safediv) or OP_MOD (safemod).
        // Matches compilers/python/runar_compiler/codegen/stack.py:_lower_safe_div_mod
        // and compilers/rust/src/codegen/stack.rs::lower_safediv / lower_safemod.
        // ------------------------------------------------------------------
        void lowerSafeDivMod(String bindingName, String funcName, List<String> args,
                             int idx, Map<String, Integer> lastUses) {
            if (args.size() < 2) {
                throw new RuntimeException(funcName + " requires 2 arguments");
            }
            String a = args.get(0);
            String b = args.get(1);

            bringToTop(a, operandConsume(a, args, idx, lastUses));
            bringToTop(b, operandConsume(b, args, idx, lastUses));

            // DUP b, assert b != 0, then divide / mod.
            // Stack: a b -> a b b -> a b (b!=0) -> [verify pops] -> a b -> a/b or a%b
            emitOp(new OpcodeOp("OP_DUP"));
            sm.push("");
            emitOp(new OpcodeOp("OP_0NOTEQUAL"));
            emitOp(new OpcodeOp("OP_VERIFY"));
            sm.pop();

            sm.pop();
            sm.pop();
            String opcode = "safediv".equals(funcName) ? "OP_DIV" : "OP_MOD";
            emitOp(new OpcodeOp(opcode));

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // percentOf(amount, bps): basis-point scaling, (amount * bps) / 10000.
        // Matches compilers/python/runar_compiler/codegen/stack.py:_lower_percent_of
        // and compilers/rust/src/codegen/stack.rs::lower_percent_of.
        // Emits: OP_MUL <10000> OP_DIV.
        // ------------------------------------------------------------------
        void lowerPercentOf(String bindingName, List<String> args, int idx,
                            Map<String, Integer> lastUses) {
            if (args.size() < 2) {
                throw new RuntimeException("percentOf requires 2 arguments");
            }
            String amount = args.get(0);
            String bps = args.get(1);

            bringToTop(amount, operandConsume(amount, args, idx, lastUses));
            bringToTop(bps, operandConsume(bps, args, idx, lastUses));

            sm.pop();
            sm.pop();
            emitOp(new OpcodeOp("OP_MUL"));
            sm.push(""); // amount * bps

            emitOp(new PushOp(PushValue.of(10000)));
            sm.push("");

            sm.pop();
            sm.pop();
            emitOp(new OpcodeOp("OP_DIV"));

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // clamp(val, lo, hi): clamp value to [lo, hi].
        // Mirrors compilers/go/codegen/stack.go::lowerClamp exactly.
        // Stack: <val> <lo> -> OP_MAX -> max(val,lo); push hi -> OP_MIN.
        // ------------------------------------------------------------------
        void lowerClamp(String bindingName, List<String> args, int idx,
                        Map<String, Integer> lastUses) {
            if (args.size() < 3) {
                throw new RuntimeException("clamp requires 3 arguments");
            }
            String val = args.get(0);
            String lo = args.get(1);
            String hi = args.get(2);

            bringToTop(val, operandConsume(val, args, idx, lastUses));
            bringToTop(lo, operandConsume(lo, args, idx, lastUses));
            sm.pop();
            sm.pop();
            emitOp(new OpcodeOp("OP_MAX"));
            sm.push(""); // intermediate max(val, lo)

            bringToTop(hi, operandConsume(hi, args, idx, lastUses));
            sm.pop();
            sm.pop();
            emitOp(new OpcodeOp("OP_MIN"));

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // pow(base, exp): exponentiation via 32-iteration conditional-multiply
        // unrolled loop. Mirrors compilers/go/codegen/stack.go::lowerPow.
        // Strategy: <base> <exp> swap, push 1; 32 rounds of:
        //   push 2, OP_PICK (get exp), push i, OP_GREATERTHAN,
        //   IF { over, OP_MUL }
        // Then nip nip to drop exp + base, leaving result.
        // ------------------------------------------------------------------
        void lowerPow(String bindingName, List<String> args, int idx,
                      Map<String, Integer> lastUses) {
            if (args.size() < 2) {
                throw new RuntimeException("pow requires 2 arguments");
            }
            String base = args.get(0);
            String exp = args.get(1);

            bringToTop(base, operandConsume(base, args, idx, lastUses));
            bringToTop(exp, operandConsume(exp, args, idx, lastUses));
            sm.pop();
            sm.pop();

            emitOp(new SwapOp());                          // exp base
            emitOp(new PushOp(PushValue.of(1)));           // exp base 1(acc)

            final int maxPowIterations = 32;
            for (int i = 0; i < maxPowIterations; i++) {
                emitOp(new PushOp(PushValue.of(2)));
                emitOp(new OpcodeOp("OP_PICK"));            // exp base acc exp
                emitOp(new PushOp(PushValue.of(i)));
                emitOp(new OpcodeOp("OP_GREATERTHAN"));     // exp base acc (exp>i)
                List<StackOp> thenOps = new ArrayList<>();
                thenOps.add(new OverOp());                  // exp base acc base
                thenOps.add(new OpcodeOp("OP_MUL"));        // exp base (acc*base)
                emitOp(new IfOp(thenOps));
            }
            emitOp(new NipOp()); // exp result
            emitOp(new NipOp()); // result

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // mulDiv(a, b, c): (a * b) / c. Mirrors lowerMulDiv in Go.
        // Stack: <a> <b> -> OP_MUL -> (a*b); push c -> OP_DIV.
        // ------------------------------------------------------------------
        void lowerMulDiv(String bindingName, List<String> args, int idx,
                         Map<String, Integer> lastUses) {
            if (args.size() < 3) {
                throw new RuntimeException("mulDiv requires 3 arguments");
            }
            String a = args.get(0);
            String b = args.get(1);
            String c = args.get(2);

            bringToTop(a, operandConsume(a, args, idx, lastUses));
            bringToTop(b, operandConsume(b, args, idx, lastUses));
            sm.pop();
            sm.pop();
            emitOp(new OpcodeOp("OP_MUL"));
            sm.push(""); // a*b

            bringToTop(c, operandConsume(c, args, idx, lastUses));
            sm.pop();
            sm.pop();
            emitOp(new OpcodeOp("OP_DIV"));

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // sqrt(n): integer square root via 16-iteration Newton's method.
        // Mirrors lowerSqrt in Go: guarded for n == 0 (skip Newton, leave 0).
        // OP_DUP IF { OP_DUP; 16x (over, over, OP_DIV, OP_ADD, push 2, OP_DIV); nip }
        // ------------------------------------------------------------------
        void lowerSqrt(String bindingName, List<String> args, int idx,
                       Map<String, Integer> lastUses) {
            if (args.size() < 1) {
                throw new RuntimeException("sqrt requires 1 argument");
            }
            String n = args.get(0);

            bringToTop(n, isLastUse(n, idx, lastUses));
            sm.pop();

            emitOp(new OpcodeOp("OP_DUP")); // n n

            List<StackOp> newtonOps = new ArrayList<>();
            newtonOps.add(new OpcodeOp("OP_DUP")); // n guess(=n)
            final int sqrtIterations = 16;
            for (int i = 0; i < sqrtIterations; i++) {
                newtonOps.add(new OverOp());                       // n guess n
                newtonOps.add(new OverOp());                       // n guess n guess
                newtonOps.add(new OpcodeOp("OP_DIV"));             // n guess (n/guess)
                newtonOps.add(new OpcodeOp("OP_ADD"));             // n (guess + n/guess)
                newtonOps.add(new PushOp(PushValue.of(2)));        // n (guess + n/guess) 2
                newtonOps.add(new OpcodeOp("OP_DIV"));             // n new_guess
            }
            newtonOps.add(new NipOp()); // result (drop n)

            emitOp(new IfOp(newtonOps));

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // gcd(a, b): Euclidean algorithm, bounded to 256 iterations.
        // Mirrors lowerGcd in Go. Both operands forced to absolute value
        // first; each iteration: OP_DUP OP_0NOTEQUAL IF { OP_TUCK OP_MOD }
        // Final OP_DROP removes the trailing zero.
        // ------------------------------------------------------------------
        void lowerGcd(String bindingName, List<String> args, int idx,
                      Map<String, Integer> lastUses) {
            if (args.size() < 2) {
                throw new RuntimeException("gcd requires 2 arguments");
            }
            String a = args.get(0);
            String b = args.get(1);

            bringToTop(a, operandConsume(a, args, idx, lastUses));
            bringToTop(b, operandConsume(b, args, idx, lastUses));
            sm.pop();
            sm.pop();

            // Stack: a b -> |a| swap |b| swap -> |a| |b|
            emitOp(new OpcodeOp("OP_ABS"));
            emitOp(new SwapOp());
            emitOp(new OpcodeOp("OP_ABS"));
            emitOp(new SwapOp());

            final int gcdIterations = 256;
            for (int i = 0; i < gcdIterations; i++) {
                emitOp(new OpcodeOp("OP_DUP"));        // a b b
                emitOp(new OpcodeOp("OP_0NOTEQUAL"));  // a b (b!=0)
                List<StackOp> thenOps = new ArrayList<>();
                thenOps.add(new OpcodeOp("OP_TUCK")); // b a b
                thenOps.add(new OpcodeOp("OP_MOD"));   // b (a%b)
                emitOp(new IfOp(thenOps));
            }
            emitOp(new DropOp()); // drop the trailing 0

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // divmod(a, b): returns quotient (drops remainder).
        // Mirrors lowerDivmod in Go. OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD drop.
        // ------------------------------------------------------------------
        void lowerDivmod(String bindingName, List<String> args, int idx,
                         Map<String, Integer> lastUses) {
            if (args.size() < 2) {
                throw new RuntimeException("divmod requires 2 arguments");
            }
            String a = args.get(0);
            String b = args.get(1);

            bringToTop(a, operandConsume(a, args, idx, lastUses));
            bringToTop(b, operandConsume(b, args, idx, lastUses));
            sm.pop();
            sm.pop();

            emitOp(new OpcodeOp("OP_2DUP")); // a b a b
            emitOp(new OpcodeOp("OP_DIV"));  // a b (a/b)
            emitOp(new OpcodeOp("OP_ROT"));  // b (a/b) a
            emitOp(new OpcodeOp("OP_ROT"));  // (a/b) a b
            emitOp(new OpcodeOp("OP_MOD"));  // (a/b) (a%b)
            emitOp(new DropOp());            // (a/b)

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // log2(n): floor(log2(n)) via 64-iteration bit-scan.
        // Mirrors lowerLog2 in Go. push 0 (counter); each iteration:
        //   swap, OP_DUP, push 1, OP_GREATERTHAN,
        //   IF { push 2, OP_DIV, swap, OP_1ADD, swap }, swap.
        // Final OP_NIP drops the input, leaving counter.
        // ------------------------------------------------------------------
        void lowerLog2(String bindingName, List<String> args, int idx,
                       Map<String, Integer> lastUses) {
            if (args.size() < 1) {
                throw new RuntimeException("log2 requires 1 argument");
            }
            String n = args.get(0);

            bringToTop(n, isLastUse(n, idx, lastUses));
            sm.pop();

            emitOp(new PushOp(PushValue.of(0))); // n 0

            final int log2Iterations = 64;
            for (int i = 0; i < log2Iterations; i++) {
                emitOp(new SwapOp());                  // counter input
                emitOp(new OpcodeOp("OP_DUP"));        // counter input input
                emitOp(new PushOp(PushValue.of(1)));   // counter input input 1
                emitOp(new OpcodeOp("OP_GREATERTHAN")); // counter input (input>1)
                List<StackOp> thenOps = new ArrayList<>();
                thenOps.add(new PushOp(PushValue.of(2))); // counter input 2
                thenOps.add(new OpcodeOp("OP_DIV"));   // counter (input/2)
                thenOps.add(new SwapOp());             // (input/2) counter
                thenOps.add(new OpcodeOp("OP_1ADD"));  // (input/2) (counter+1)
                thenOps.add(new SwapOp());             // (counter+1) (input/2)
                emitOp(new IfOp(thenOps));
                emitOp(new SwapOp());                  // input counter
            }
            emitOp(new NipOp()); // counter

            sm.push(bindingName);
            trackDepth();
        }

        // ------------------------------------------------------------------
        // sign(x): return -1/0/+1 without dividing by zero.
        // Mirrors lowerSign in Go. OP_DUP IF { OP_DUP OP_ABS swap OP_DIV }
        // For x == 0, the dup'd 0 is consumed by the IF and original 0 stays.
        // ------------------------------------------------------------------
        void lowerSign(String bindingName, List<String> args, int idx,
                       Map<String, Integer> lastUses) {
            if (args.size() < 1) {
                throw new RuntimeException("sign requires 1 argument");
            }
            String x = args.get(0);

            bringToTop(x, isLastUse(x, idx, lastUses));
            sm.pop();

            emitOp(new OpcodeOp("OP_DUP"));
            List<StackOp> thenOps = new ArrayList<>();
            thenOps.add(new OpcodeOp("OP_DUP"));
            thenOps.add(new OpcodeOp("OP_ABS"));
            thenOps.add(new SwapOp());
            thenOps.add(new OpcodeOp("OP_DIV"));
            emitOp(new IfOp(thenOps));

            sm.push(bindingName);
            trackDepth();
        }

        // ---------------- method_call ----------------

        void lowerMethodCall(String bindingName, String obj, String method,
                             List<String> args, int idx, Map<String, Integer> lastUses) {
            if ("getStateScript".equals(method)) {
                if (sm.has(obj)) {
                    bringToTop(obj, true);
                    emitOp(new DropOp());
                    sm.pop();
                }
                lowerGetStateScript(bindingName);
                return;
            }
            AnfMethod pm = privateMethods.get(method);
            if (pm != null) {
                if (sm.has(obj)) {
                    bringToTop(obj, true);
                    emitOp(new DropOp());
                    sm.pop();
                }
                inlineMethodCall(bindingName, pm, args, idx, lastUses);
                return;
            }
            // Treat as a function call
            lowerCall(bindingName, method, args, idx, lastUses);
        }

        void inlineMethodCall(String bindingName, AnfMethod m, List<String> args,
                              int idx, Map<String, Integer> lastUses) {
            List<Map<String, String>> shadowed = new ArrayList<>();
            for (int i = 0; i < args.size() && i < m.params().size(); i++) {
                String paramName = m.params().get(i).name();
                String arg = args.get(i);
                bringToTop(arg, operandConsume(arg, args, idx, lastUses));
                sm.pop();

                if (sm.has(paramName)) {
                    int existingDepth = sm.findDepth(paramName);
                    String shadowName = "__shadowed_" + idx + "_" + paramName;
                    sm.renameAtDepth(existingDepth, shadowName);
                    Map<String, String> entry = new HashMap<>();
                    entry.put("paramName", paramName);
                    entry.put("shadowName", shadowName);
                    shadowed.add(entry);
                }
                sm.push(paramName);
            }

            lowerBindings(m.body(), false);

            for (Map<String, String> e : shadowed) {
                String sn = e.get("shadowName");
                String pn = e.get("paramName");
                if (sm.has(sn)) {
                    int d = sm.findDepth(sn);
                    sm.renameAtDepth(d, pn);
                }
            }

            if (!m.body().isEmpty()) {
                String lastName = m.body().get(m.body().size() - 1).name();
                if (sm.depth() > 0 && lastName.equals(sm.peekAtDepth(0))) {
                    sm.pop();
                    sm.push(bindingName);
                }
            }
        }

        // ---------------- if ----------------


        /**
         * {@code results} is the {@code if} node's declared result slots,
         * deepest first (see {@link If#results()}). Empty for an {@code if}
         * that carries at most one result, and then every path below behaves
         * exactly as it did before the multi-result contract existed.
         */
        void lowerIf(String bindingName, String cond,
                     List<AnfBinding> thenB, List<AnfBinding> elseB,
                     List<String> results,
                     int idx, Map<String, Integer> lastUses,
                     boolean terminalAssert) {
            // The ANF wire format has no version field, and --ir / --ir-parity
            // are documented surfaces that feed a checked-in ANF JSON straight
            // into this pass. An ANF produced BEFORE the multi-result node
            // carries the trailing `__merge$` block WITHOUT results — back then
            // the block was a naming CONVENTION this pass recognised, and no
            // tier recognises it any more. It deserialises cleanly, the declared
            // count is 0, and the result count falls back to
            // thenDepth - parentDepth, which counts the arm's untrimmed block
            // residue as results. Refuse it: the block can only be emitted by
            // appendBranchResults, which only runs for an `if` that declares
            // results. Emits no opcodes.
            if (results == null || results.isEmpty()) {
                List<AnfBinding> arms = new ArrayList<>();
                if (thenB != null) arms.addAll(thenB);
                if (elseB != null) arms.addAll(elseB);
                for (AnfBinding b : arms) {
                    if (b.name().startsWith(AnfValue.MERGED_LOCAL_TEMP_PREFIX)) {
                        throw new IllegalStateException(
                            "ANF produced by a pre-multi-result compiler: the "
                            + "conditional's arm carries a '"
                            + AnfValue.MERGED_LOCAL_TEMP_PREFIX + "' block but the node "
                            + "declares no results (binding '" + b.name() + "'). That "
                            + "block used to be a naming convention this pass inferred "
                            + "results from; it is now a declared contract, and no tier "
                            + "reads the convention any more. Recompile the source with "
                            + "the current compiler instead of reusing the stored ANF. "
                            + "binding='" + bindingName + "'.");
                    }
                }
            }

            // Result slots are identified BY NAME — two identically-named
            // results are indistinguishable, so the layout assertion would be
            // satisfied by coincidence while one value silently replaced the
            // other. ANF lowering refuses the source shape; this guards the
            // --ir path, where the list arrives as data.
            if (results != null && results.size() > 1
                && new LinkedHashSet<>(results).size() != results.size()) {
                throw new IllegalStateException(
                    "Internal codegen error: the conditional declares duplicate result "
                    + "names [" + String.join(", ", results) + "]. Result slots are "
                    + "matched by name, so duplicates cannot be told apart and one "
                    + "value would silently replace the other. binding='"
                    + bindingName + "'.");
            }

            // NEW-015: does an ARM read the condition again?
            //
            // lastUses is keyed by the index of the ENCLOSING binding, and
            // collectRefs deliberately recurses into thenBranch / elseBranch so
            // an arm-only ref is not dropped early. Both facts together mean an
            // arm's read of the condition lands on THIS binding's index —
            // indistinguishable from a ref used only as the condition.
            // isLastUse then said "yes, consume it", bringToTop ROLLed the slot
            // away, and the arm looked for a value that was no longer there:
            //
            //     let f: boolean = c > 0n;
            //     assert(f ? c > 10n : !f);
            //     //  Value 'f' not found on stack (stack has 1 items: [c])
            //
            // Legal source, accepted by validate and typecheck, rejected here —
            // so there was no diagnostic a developer could act on. It only ever
            // bit when the condition local was DEAD after the `if`; one that
            // stayed live was already covered by the `> idx` rule below, which
            // is why the shape looked like it worked. && / || desugar to this
            // node, so `f || !f` routes through the same path.
            boolean condReadInArms = false;
            for (AnfBinding b : thenB) {
                if (collectRefs(b.value()).contains(cond)) { condReadInArms = true; break; }
            }
            if (!condReadInArms) {
                for (AnfBinding b : elseB) {
                    if (collectRefs(b.value()).contains(cond)) { condReadInArms = true; break; }
                }
            }

            bringToTop(cond, !condReadInArms && isLastUse(cond, idx, lastUses));
            sm.pop();

            Set<String> protectedRefs = new LinkedHashSet<>();
            for (Map.Entry<String, Integer> e : lastUses.entrySet()) {
                if (e.getValue() > idx && sm.has(e.getKey())) {
                    protectedRefs.add(e.getKey());
                }
            }

            // A condition the arms re-read was PICKed just above, so the slot
            // survived OP_IF. Protect it for the same reason the merged-local
            // block below is protected: only ONE arm may hold the read, so
            // letting that arm consume the slot would leave the two arms at
            // different depths over a name the parent still models.
            if (condReadInArms && sm.has(cond)) protectedRefs.add(cond);

            // The K>=2 merged-local block reads every merged local in BOTH
            // arms, and that read is RECONCILIATION, not a use: it is what
            // makes each arm leave exactly K equally-named result slots for the
            // N>=2 reconcile below to adopt. So the merged locals must be
            // copied, never consumed — regardless of whether the ENCLOSING
            // scope reads them again.
            //
            // appendMergedLocalResults (ANF lowering) states that as its
            // premise: "pass 1 always COPIES ... because a local live after the
            // `if` is in outerProtectedRefs". Enclosing-scope liveness is the
            // wrong question, and the premise silently failed for every merged
            // local whose last enclosing use IS this `if` — which is EVERY
            // merged local of an `if` in a loop body, since the body's last-use
            // map ends at the `if` itself.
            //
            // What happened then: pass 1 ROLLED instead of picking, the arm's
            // stack effect stopped being +K, the arms ended at different
            // depths, phase 3 padded the shortfall with EMPTY pushes, the
            // N-result layout check saw an unnamed slot where it needed the
            // merged name, and control fell through to the single-slot fallback
            // push(bindingName) — ONE stackMap name registered for K physical
            // results, with acc/wacc still naming the dead pre-`if` slots.
            // `for (i<2) { if (i<5) { acc = acc + step; wacc = wacc + acc; } }`
            // with step = 3 produced wacc = 3 where the source says 9: silently
            // in a stateless contract, and as a permanently unspendable UTXO in
            // a stateful one.
            //
            // Byte-neutral for every program whose merged locals were already
            // live after the `if`: those names are already protected above,
            // which is precisely why those programs compiled correctly.
            //
            // Now driven by the node's DECLARED results instead of by
            // recognising a trailing `__merge$` block, so an arm-written
            // property is protected on the same footing as a rebound local.
            for (String name : results) {
                if (sm.has(name)) protectedRefs.add(name);
            }

            Set<String> preIfNames = sm.namedSlots();

            LoweringContext thenCtx = subContext();
            thenCtx.outerProtectedRefs = protectedRefs;
            thenCtx.insideBranch = true;
            thenCtx.lowerBindings(thenB, terminalAssert);

            thenCtx.drainBranchPrivateResidue(preIfNames);

            if (terminalAssert && thenCtx.sm.depth() > 1) {
                int excess = thenCtx.sm.depth() - 1;
                for (int i = 0; i < excess; i++) {
                    thenCtx.emitOp(new NipOp());
                    thenCtx.sm.removeAtDepth(1);
                }
            }

            LoweringContext elseCtx = subContext();
            elseCtx.outerProtectedRefs = protectedRefs;
            elseCtx.insideBranch = true;
            elseCtx.lowerBindings(elseB, terminalAssert);

            elseCtx.drainBranchPrivateResidue(preIfNames);

            if (terminalAssert && elseCtx.sm.depth() > 1) {
                int excess = elseCtx.sm.depth() - 1;
                for (int i = 0; i < excess; i++) {
                    elseCtx.emitOp(new NipOp());
                    elseCtx.sm.removeAtDepth(1);
                }
            }

            // Phase 1: consumed-name analysis.
            //
            // NEW-018: counted by MULTIPLICITY, not by name-set membership.
            //
            // A parent stack legitimately holds the same name in more than one
            // slot — a loop rebinding a local leaves one slot per unrolled
            // iteration, all named `acc`, of which only the shallowest is ever
            // read (the model resolves a name to its shallowest slot). When an
            // arm ROLLs that live slot away, the name is STILL in the arm's name
            // SET because the dead residue slot beneath it carries the same name
            // — so the set-difference this phase used to compute saw nothing
            // consumed, emitted no matching drop in the sibling, and left the
            // two arms one slot apart.
            //
            // Phase 3 then "fixed" the depth with an anonymous pad. A pad
            // restores the COUNT but not the POSITION: the arm that lost a slot
            // from the middle of the region gets a placeholder next to its
            // result, while the sibling still holds the real value in the
            // original slot. The two arms leave positionally different stacks,
            // the parent adopts one of them, and every slot the other arm holds
            // below the result is off by one:
            //
            //     let acc = p; let wacc = 0n;
            //     for (…) for (…) { acc = acc + p; wacc = wacc + acc; }
            //     let br0 = 0n; const sib0 = p;
            //     if (p === 0n) { br0 = p; }
            //     assert((p >= 0n ? acc >= 0n : false) ? (br0 < sib0) : false);
            //
            // The inner conditional is the CONDITION of the outer one. Its
            // then-arm consumes the live `acc`; the parent holds `acc` twice, so
            // phase 1 missed it and the arms came back as `[t · br0 sib0 …]`
            // against `[t br0 sib0 acc …]`. With p = 1 the source ACCEPTS and
            // the AST interpreter accepts; the script engines reject the spend
            // with "The top stack element must be truthy after script
            // evaluation" — an ordinary contract deployed to a permanently
            // unspendable UTXO. It needs no `&&`: a plain nested ternary reaches
            // it, and `a && b && c` is left-associative, so it is also what
            // blocked the short-circuit desugar.
            //
            // Counting occurrences instead makes the sibling drop its matching
            // slot, both arms end at the same depth with the same layout, and no
            // pad is needed at all. Byte-neutral for every parent stack with no
            // duplicated name: for a name held once, "parent has 1, arm has 0"
            // is exactly the old `!postThenNames.contains(n)`, and the drop
            // depths are the same list.
            Map<String, Integer> preIfCounts = sm.nameCounts();
            Map<String, Integer> thenCounts = thenCtx.sm.nameCounts();
            Map<String, Integer> elseCounts = elseCtx.sm.nameCounts();
            List<String> consumedNames = new ArrayList<>();
            List<String> elseConsumedNames = new ArrayList<>();
            for (Map.Entry<String, Integer> e : preIfCounts.entrySet()) {
                String n = e.getKey();
                int held = e.getValue();
                int thenLost = Math.max(0, held - thenCounts.getOrDefault(n, 0));
                int elseLost = Math.max(0, held - elseCounts.getOrDefault(n, 0));
                for (int i = 0; i < thenLost - elseLost; i++) consumedNames.add(n);
                for (int i = 0; i < elseLost - thenLost; i++) elseConsumedNames.add(n);
            }

            if (!consumedNames.isEmpty()) {
                for (int d : elseCtx.sm.dropDepthsFor(consumedNames)) dropAtDepth(elseCtx, d);
            }
            if (!elseConsumedNames.isEmpty()) {
                for (int d : thenCtx.sm.dropDepthsFor(elseConsumedNames)) dropAtDepth(thenCtx, d);
            }

            // Branch-merged locals: trim each arm down to exactly its K
            // result slots.
            //
            // ANF lowering ends both arms with an identical K-binding block
            // that rebinds every merged local from a `__merge$<i>` temp (see
            // appendMergedLocalResults). That block leaves the K live values on
            // top in the same canonical order in both arms — but BENEATH them
            // each arm still holds whatever its own body produced, and those
            // differ per arm, which is exactly what the N>=2 reconcile further
            // down compares. Everything beneath the K results is dead: the
            // block copied each merged local before rebinding it, and a
            // branch-local binding is not visible after the `if`.
            //
            // Runs AFTER the phase-2 consumption drops, so both arms have given
            // up the same parent slots and share one base depth.
            //
            // NEW-018: counted by MULTIPLICITY, for the same reason phase 1 is.
            // Phase 1 now makes both arms give up the same slot of a name the
            // parent holds twice, so the base depth has to count that slot as
            // given up too — otherwise targetDepth is one too high, the trim
            // below does nothing, and the layout assertion fires on a program
            // that is actually well-formed.
            int nDeclared = results.size();
            if (nDeclared >= 1) {
                Map<String, Integer> stillHeldCounts = thenCtx.sm.nameCounts();
                int consumedFromParent = 0;
                for (Map.Entry<String, Integer> e : preIfCounts.entrySet()) {
                    consumedFromParent +=
                        Math.max(0, e.getValue() - stillHeldCounts.getOrDefault(e.getKey(), 0));
                }
                int targetDepth = sm.depth() - consumedFromParent + nDeclared;
                for (LoweringContext armCtx : List.of(thenCtx, elseCtx)) {
                    while (armCtx.sm.depth() > targetDepth) {
                        armCtx.dropSlotAtDepth(nDeclared);
                    }
                }

                // The declared contract, checked rather than assumed: after the
                // trim, each arm's top N slots must BE the declared results, in
                // the declared order (results[0] deepest). appendBranchResults
                // is what makes this true; if it ever stops being true the arms
                // disagree on layout, which is precisely the failure that
                // produced the 2026-08 miscompile family. Emits no opcodes.
                String[] labels = { "then", "else" };
                List<LoweringContext> arms = List.of(thenCtx, elseCtx);
                for (int ai = 0; ai < arms.size(); ai++) {
                    LoweringContext armCtx = arms.get(ai);
                    if (armCtx.sm.depth() != targetDepth) {
                        throw new IllegalStateException(
                            "Internal codegen error: branch result layout mismatch — the "
                            + labels[ai] + "-arm of the conditional ends at depth "
                            + armCtx.sm.depth() + ", but its " + nDeclared
                            + " declared result(s) require depth " + targetDepth
                            + ". binding='" + bindingName + "'.");
                    }
                    for (int i = 0; i < nDeclared; i++) {
                        String want = results.get(nDeclared - 1 - i);
                        String got = armCtx.sm.peekAtDepth(i);
                        if (!want.equals(got)) {
                            throw new IllegalStateException(
                                "Internal codegen error: branch result layout mismatch — the "
                                + labels[ai] + "-arm of the conditional holds '" + got
                                + "' where the node declares '" + want + "' (slot "
                                + (nDeclared - 1 - i) + " of [" + String.join(", ", results)
                                + "]). Every later operand would resolve to the wrong slot. "
                                + "binding='" + bindingName + "'.");
                        }
                    }
                }
            }

            // Phase 3: depth-balance reconciliation after ALL drops.
            //
            // Compensate the FULL depth difference between the branches — NOT
            // just a single item. A conditional write of N state fields leaves
            // N result values on the then-branch, so the (empty) else-branch
            // must preserve N old values. Issue #99 Bug 1: the previous
            // single-shot check only balanced a 1-item difference, leaving
            // N>=2 conditional writes imbalanced by (N-1) and the update branch
            // unspendable. For each missing slot, when the then-branch
            // reassigned a variable (if-without-else), push a COPY of that
            // same-named (old) value in the else-branch; otherwise push a
            // generic placeholder. Process deepest-to-top so copies land in
            // the same order.
            while (thenCtx.sm.depth() > elseCtx.sm.depth()) {
                int resultDepth = thenCtx.sm.depth() - elseCtx.sm.depth() - 1;
                String thenName = thenCtx.sm.peekAtDepth(resultDepth);
                if (elseB.isEmpty() && thenName != null && !thenName.isEmpty() && elseCtx.sm.has(thenName)) {
                    int varDepth = elseCtx.sm.findDepth(thenName);
                    if (varDepth == 0) {
                        elseCtx.emitOp(new DupOp());
                    } else {
                        elseCtx.emitOp(new PushOp(PushValue.of(varDepth)));
                        elseCtx.sm.push("");
                        elseCtx.emitOp(new PickOp(varDepth));
                        elseCtx.sm.pop();
                    }
                    elseCtx.sm.push(thenName);
                } else {
                    elseCtx.emitOp(new PushOp(PushValue.ofHex("")));
                    elseCtx.sm.push("");
                }
            }
            while (elseCtx.sm.depth() > thenCtx.sm.depth()) {
                thenCtx.emitOp(new PushOp(PushValue.ofHex("")));
                thenCtx.sm.push("");
            }

            // Layer B — branch-balance invariant (#99 Bug 1 guard).
            // After reconciliation the two arms of an OP_IF/OP_ELSE MUST leave
            // the stack at identical depth; otherwise the code after OP_ENDIF
            // (generated against a single assumed depth) is only correct for
            // whichever branch the spender does not take, producing a silently
            // unspendable script. The Script VM does not enforce branch
            // balance, so this is the compiler's responsibility. A failure here
            // is a codegen bug, never a user error — fail loudly at compile
            // time instead of on-chain.
            if (thenCtx.sm.depth() != elseCtx.sm.depth()) {
                throw new RuntimeException(
                    "Internal codegen error: conditional in method emitted stack-imbalanced "
                    + "branches (then depth " + thenCtx.sm.depth() + " != else depth "
                    + elseCtx.sm.depth() + "). This would produce an unspendable script "
                    + "(see GitHub issue #99). binding='" + bindingName + "'.");
            }

            // NEW-018 needs the arms' post-branch name MULTISET. Snapshotted here
            // because the arms' op lists are consumed immediately after this point.
            Map<String, Integer> postBranchCounts = thenCtx.sm.nameCounts();

            IfOp ifOp;
            if (!elseCtx.ops.isEmpty()) {
                ifOp = new IfOp(thenCtx.ops, elseCtx.ops);
            } else {
                ifOp = new IfOp(thenCtx.ops);
            }
            emitOp(ifOp);

            // Physical slots this method drops AFTER OP_ENDIF, while
            // reconciling the parent stackMap against the arms' results.
            // Counted because the invariant at the end of lowerIf cannot compare
            // the two depths directly: the post-ENDIF reconcile legitimately
            // ROLL/DROPs stale slots out from under the results, so those drops
            // have to be added back before comparing.
            int postEndifDrops = 0;

            // Reconcile parent stackMap with consumed names in both branches.
            //
            // NEW-018: counted by MULTIPLICITY, for the same reason phase 1 is.
            // When the arms consume the live slot of a name the parent holds
            // twice, the parent must give up one slot too — the set test kept
            // both, so the parent modelled one more slot than the arms
            // physically left and the adopt below saw armDepth == parentDepth
            // and pushed nothing at all.
            for (Map.Entry<String, Integer> e : preIfCounts.entrySet()) {
                String n = e.getKey();
                int excess = e.getValue() - postBranchCounts.getOrDefault(n, 0);
                while (excess > 0 && sm.has(n)) {
                    sm.removeAtDepth(sm.findDepth(n));
                    excess--;
                }
            }

            // C27: the N>=2 result reconcile below also applies when the else-
            // branch is PRESENT and BOTH arms wrote the same N mutable fields
            // (e.g. each branch runs `this.a = ...; this.b = ...`). This is the
            // else-present twin of the empty-else fix (#99 Bug 1). Without it,
            // lowerIf falls through to `push(bindingName)` further down —
            // registering ONE stackMap name for N physical results — so the
            // state serialization emits against the wrong slot (OP_NUM2BIN on a
            // byte string) and the continuation is unspendable (a funds-safety
            // bug). Only fire when both arms leave the identical top-N property
            // names in the identical order, so a single post-ENDIF reconcile is
            // valid regardless of which branch the spender takes. The single-
            // field same-property case (N==1, "turn flip") is unaffected — it
            // still takes the dedicated path below.
            int nResults = thenCtx.sm.depth() - sm.depth();
            boolean elseMatchesThenNResultLayout =
                !elseB.isEmpty()
                && nResults >= 2
                && elseCtx.sm.depth() - sm.depth() == nResults;
            if (elseMatchesThenNResultLayout) {
                for (int i = 0; i < nResults; i++) {
                    String tn = thenCtx.sm.peekAtDepth(i);
                    if (tn == null || tn.isEmpty() || !tn.equals(elseCtx.sm.peekAtDepth(i))) {
                        elseMatchesThenNResultLayout = false;
                        break;
                    }
                }
            }

            // If expression may produce a result value on top
            if (nDeclared >= 1) {
                // DECLARED RESULTS. Both arms were normalised by
                // appendBranchResults and the layout check above proved they
                // hold exactly `results`, so the parent adopts them BY THE
                // DECLARED ORDER — no counting of trailing `__merge$` bindings,
                // no comparison of arm depths, no inference of which names are
                // still live. results[0] is the deepest slot, matching the order
                // pass 2 of the normalisation rebound them in.
                //
                // Then each parent slot the block shadows (the pre-`if` binding
                // of a merged local, the stale value of a written property) is
                // physically rolled out from under the results, exactly as the
                // pre-existing N>=2 reconcile did — which is why the four
                // `__merge$` goldens keep their bytes.
                for (String name : results) {
                    sm.push(name);
                }
                // How far below the result block the deepest stale slot sat.
                // Adopting a result puts it ON TOP, but its pre-`if` binding
                // lived at depth `d`, i.e. BENEATH the `d - nDeclared` slots in
                // between. Removing the stale copy does not reorder those, so
                // the adopted result has crossed them: the layout is rotated
                // even though the NAME SET and the DEPTH are both unchanged.
                // Invisible to the reconcile's name-set check and to Layer C's
                // depth check — the whole of issue #149.
                int sinkBelow = 0;
                for (int i = nDeclared - 1; i >= 0; i--) {
                    String name = results.get(i);
                    for (int d = nDeclared; d < sm.depth(); d++) {
                        if (name.equals(sm.peekAtDepth(d))) {
                            emitOp(new PushOp(PushValue.of(d)));
                            sm.push("");
                            emitOp(new RollOp(d + 1));
                            sm.pop();
                            String rolled = sm.removeAtDepth(d);
                            sm.push(rolled);
                            emitOp(new DropOp());
                            sm.pop();
                            postEndifDrops++;
                            if (d - nDeclared > sinkBelow) {
                                sinkBelow = d - nDeclared;
                            }
                            break;
                        }
                    }
                }

                // Restore the inherited layout: sink the result block back
                // under the `sinkBelow` slots it just crossed, so BOTH paths of
                // the enclosing `if` leave the same slot order and every
                // post-OP_ENDIF read resolves against the layout it was
                // generated for. Rolling the deepest item of the
                // (nDeclared + sinkBelow) window to the top, `sinkBelow` times,
                // lifts those slots back above the results while preserving
                // their own relative order.
                //
                // Applied unconditionally, NOT gated on this `if`'s own else:
                // the asymmetry belongs to the ENCLOSING `if`, which lowerIf
                // cannot see from here. Gating on an empty else was measured in
                // the TS tier and is WRONG — the #149 inner `if` HAS a real
                // else, so the gate disables the repair exactly where it is
                // needed.
                if (sinkBelow > 0) {
                    int windowSize = nDeclared + sinkBelow;
                    for (int j = 0; j < sinkBelow; j++) {
                        emitOp(new PushOp(PushValue.of(windowSize - 1)));
                        sm.push("");
                        emitOp(new RollOp(windowSize));
                        sm.pop();
                        String lifted = sm.removeAtDepth(windowSize - 1);
                        sm.push(lifted);
                    }
                }
            } else if (thenCtx.sm.depth() > sm.depth()
                && nResults >= 2
                && (elseB.isEmpty() || elseMatchesThenNResultLayout)) {
                // #99 Bug 1: a conditional write of N>=2 state fields leaves N
                // result values on top (new values if taken, preserved old
                // values if skipped). Record the N results in their on-stack
                // order, then physically remove the N stale old property values
                // that now sit beneath the result block.
                int resultCount = thenCtx.sm.depth() - sm.depth();
                for (int i = resultCount - 1; i >= 0; i--) {
                    String nm = thenCtx.sm.peekAtDepth(i);
                    sm.push((nm == null || nm.isEmpty()) ? bindingName : nm);
                }
                List<String> resultNames = new ArrayList<>();
                for (int i = 0; i < resultCount; i++) resultNames.add(sm.peekAtDepth(i));
                for (String name : resultNames) {
                    if (name == null || name.isEmpty()) continue;
                    for (int d = resultCount; d < sm.depth(); d++) {
                        if (name.equals(sm.peekAtDepth(d))) {
                            emitOp(new PushOp(PushValue.of(d)));
                            sm.push("");
                            emitOp(new RollOp(d + 1));
                            sm.pop();
                            String rolled = sm.removeAtDepth(d);
                            sm.push(rolled);
                            emitOp(new DropOp());
                            sm.pop();
                            postEndifDrops++;
                            break;
                        }
                    }
                }
            } else if (thenCtx.sm.depth() > sm.depth()) {
                String thenTop = thenCtx.sm.peekAtDepth(0);
                String elseTop = elseCtx.sm.depth() > 0 ? elseCtx.sm.peekAtDepth(0) : "";
                boolean isProperty = false;
                for (AnfProperty p : properties) if (p.name().equals(thenTop)) { isProperty = true; break; }
                if (isProperty && thenTop != null && !thenTop.isEmpty() && thenTop.equals(elseTop)
                    && !thenTop.equals(bindingName) && sm.has(thenTop)) {
                    sm.push(thenTop);
                    postEndifDrops += rebalanceDuplicate(thenTop);
                } else if (thenTop != null && !thenTop.isEmpty() && !isProperty
                    && elseB.isEmpty() && !thenTop.equals(bindingName) && sm.has(thenTop)) {
                    sm.push(thenTop);
                    postEndifDrops += rebalanceDuplicate(thenTop);
                } else {
                    sm.push(bindingName);
                }
            } else if (elseCtx.sm.depth() > sm.depth()) {
                sm.push(bindingName);
            } else {
                // Otherwise a void if — don't push a phantom.
            }

            // Layer C — branch result-depth invariant.
            //
            // The stackMap is the compiler's ONLY model of the stack, so a
            // stackMap that names FEWER slots than the arms physically left is
            // not detectable anywhere downstream: every later operand silently
            // resolves N slots off. That single failure mode produced the whole
            // 2026-08 branch/loop miscompile family — wrong-but-accepted state
            // continuations at best, and scripts the interpreter rejects
            // outright (locked funds) at worst.
            //
            // What must hold when lowerIf returns: the parent stackMap describes
            // exactly the physical stack. Both arms ended at armDepth (the
            // branch-balance guard above proves they agree), OP_ENDIF changes
            // nothing, and the only physical effect after it is the
            // postEndifDrops stale-slot drops the reconcile emitted. So:
            //
            //     sm.depth() + postEndifDrops == armDepth
            //
            // The naive sm.depth() == armDepth is WRONG — the reconcile
            // legitimately ROLL/DROPs stale slots out from under the results,
            // which is exactly what postEndifDrops counts.
            //
            // A failure here is always a codegen bug, never a user error. Emits
            // no opcodes: byte-neutral by construction. Same genre as the
            // branch-balance guard (#99), added for the same reason.
            int armDepth = thenCtx.sm.depth();
            if (sm.depth() + postEndifDrops != armDepth) {
                throw new IllegalStateException(
                    "Internal codegen error: branch result depth mismatch — the parent stack "
                    + "model does not describe the physical stack after OP_ENDIF (stackMap depth "
                    + sm.depth() + " + " + postEndifDrops + " post-ENDIF drop(s) != arm depth "
                    + armDepth + "). The arms leave " + (armDepth - sm.depth() - postEndifDrops)
                    + " more physical slot(s) than the compiler recorded, so every later operand "
                    + "would resolve to the wrong slot and the script would be wrong or "
                    + "unspendable. binding='" + bindingName + "'.");
            }

            trackDepth();

            if (thenCtx.maxDepth > maxDepth) maxDepth = thenCtx.maxDepth;
            if (elseCtx.maxDepth > maxDepth) maxDepth = elseCtx.maxDepth;
        }

        /** Drops the stale duplicate of {@code name}; returns the number of
         *  physical slots removed (0 or 1) so lowerIf can count post-ENDIF
         *  drops for its result-depth invariant. */
        private int rebalanceDuplicate(String name) {
            for (int d = 1; d < sm.depth(); d++) {
                if (name.equals(sm.peekAtDepth(d))) {
                    if (d == 1) {
                        emitOp(new NipOp());
                        sm.removeAtDepth(1);
                    } else {
                        emitOp(new PushOp(PushValue.of(d)));
                        sm.push("");
                        emitOp(new RollOp(d + 1));
                        sm.pop();
                        String rolled = sm.removeAtDepth(d);
                        sm.push(rolled);
                        emitOp(new DropOp());
                        sm.pop();
                    }
                    return 1;
                }
            }
            return 0;
        }

        private static void dropAtDepth(LoweringContext ctx, int depth) {
            if (depth == 0) {
                ctx.emitOp(new DropOp());
                ctx.sm.pop();
            } else if (depth == 1) {
                ctx.emitOp(new NipOp());
                ctx.sm.removeAtDepth(1);
            } else {
                ctx.emitOp(new PushOp(PushValue.of(depth)));
                ctx.sm.push("");
                ctx.emitOp(new RollOp(depth));
                ctx.sm.pop();
                String rolled = ctx.sm.removeAtDepth(depth);
                ctx.sm.push(rolled);
                ctx.emitOp(new DropOp());
                ctx.sm.pop();
            }
        }

        // ---------------- loop ----------------

        void lowerLoop(String bindingName, int count, List<AnfBinding> body, String iterVar,
                       BigInteger start, int step,
                       Integer loopBindingIndex, Map<String, Integer> enclosingLastUses) {
            // Names (re)defined anywhere inside the loop body, nested branches
            // included. A name the body itself binds is NOT an outer ref —
            // reassigned locals (e.g. `off = off + ...` inside an if) flow
            // through lowerIf's branch-reassignment reconciliation, not through
            // protection here.
            Set<String> deepBodyBindingNames = collectDeepBindingNames(body);

            Map<String, Boolean> bodyNames = new HashMap<>();
            for (AnfBinding b : body) bodyNames.put(b.name(), true);

            // Collect ALL outer-scope refs used anywhere in the body — including
            // refs that only occur inside nested if-branches (collectRefs
            // recurses). The previous top-level-only scan missed nested
            // references: a const defined before the loop and referenced only
            // inside an if-branch was consumed by the first iteration, making
            // iteration 2 fail with "Value 'X' not found on stack".
            Set<String> outerRefs = new LinkedHashSet<>();
            for (AnfBinding b : body) {
                for (String ref : collectRefs(b.value())) {
                    if (!ref.equals(iterVar) && !deepBodyBindingNames.contains(ref)) {
                        outerRefs.add(ref);
                    }
                }
            }

            // A local the body REBINDS and then READS AGAIN in the same
            // iteration is carried across iterations through the rebound slot,
            // so it must survive the body exactly like an outer ref.
            // deepBodyBindingNames above excludes it precisely because the body
            // binds it — which is what made the updated value consumable. See
            // collectLoopCarriedRebinds.
            for (String ref : collectLoopCarriedRebinds(body)) {
                if (!ref.equals(iterVar)) {
                    outerRefs.add(ref);
                }
            }

            Map<String, Boolean> prevLocal = localBindings;
            Map<String, Boolean> newLocal = new HashMap<>(prevLocal);
            newLocal.putAll(bodyNames);
            localBindings = newLocal;

            for (int i = 0; i < count; i++) {
                // Push the iteration variable value (in case the loop body uses
                // it). Iteration `i` binds `start + i*step` (issue #121);
                // zero-start counting-up loops (start=0, step=1) reduce to
                // BigInteger.valueOf(i), preserving the historical byte-for-byte
                // lowering.
                emitOp(new PushOp(PushValue.of(
                    start.add(BigInteger.valueOf((long) i * step)))));
                sm.push(iterVar);
                Map<String, Integer> lastUses = computeLastUses(body);

                // Prevent outer-scope refs from being consumed by setting their
                // last-use beyond any body binding index:
                //  - non-final iterations: always (the next iteration re-reads them);
                //  - the FINAL iteration: when the enclosing scope still references
                //    them AFTER the loop. Previously the final iteration consumed
                //    every outer ref at its last body use, so a method param (or
                //    const) referenced after the loop was gone from the stack and
                //    was silently lowered to an OP_0/empty push — compilation
                //    succeeded, the env-based interpreter passed, but the emitted
                //    Script failed at runtime (silent interpreter <-> Script
                //    divergence).
                boolean isFinalIteration = i == count - 1;
                for (String ref : outerRefs) {
                    boolean usedAfterLoop = enclosingLastUses != null
                        && loopBindingIndex != null
                        && enclosingLastUses.getOrDefault(ref, -1) > loopBindingIndex;
                    if (!isFinalIteration || usedAfterLoop) {
                        lastUses.put(ref, body.size());
                    }
                }

                for (int j = 0; j < body.size(); j++) {
                    lowerBinding(body.get(j), j, lastUses);
                }
                if (sm.has(iterVar)) {
                    int d = sm.findDepth(iterVar);
                    if (d == 0) {
                        emitOp(new DropOp());
                        sm.pop();
                    }
                }
            }

            localBindings = prevLocal;
            trackDepth();
        }

        // ---------------- assert ----------------

        void lowerAssert(String valueRef, int idx, Map<String, Integer> lastUses, boolean terminal) {
            bringToTop(valueRef, isLastUse(valueRef, idx, lastUses));
            if (!terminal) {
                sm.pop();
                emitOp(new OpcodeOp("OP_VERIFY"));
            }
            trackDepth();
        }

        // ---------------- update_prop ----------------

        void lowerUpdateProp(String propName, String valueRef, int idx, Map<String, Integer> lastUses) {
            bringToTop(valueRef, isLastUse(valueRef, idx, lastUses));
            sm.pop();
            sm.push(propName);

            if (!insideBranch) {
                for (int d = 1; d < sm.depth(); d++) {
                    if (propName.equals(sm.peekAtDepth(d))) {
                        if (d == 1) {
                            emitOp(new NipOp());
                            sm.removeAtDepth(1);
                        } else {
                            emitOp(new PushOp(PushValue.of(d)));
                            sm.push("");
                            emitOp(new RollOp(d + 1));
                            sm.pop();
                            String rolled = sm.removeAtDepth(d);
                            sm.push(rolled);
                            emitOp(new DropOp());
                            sm.pop();
                        }
                        break;
                    }
                }
            }
            trackDepth();
        }

        // ---------------- get_state_script ----------------

        void lowerGetStateScript(String bindingName) {
            List<AnfProperty> stateProps = new ArrayList<>();
            for (AnfProperty p : properties) if (!p.readonly()) stateProps.add(p);

            if (stateProps.isEmpty()) {
                emitOp(new PushOp(PushValue.ofHex("")));
                sm.push(bindingName);
                return;
            }

            boolean first = true;
            for (AnfProperty prop : stateProps) {
                if (sm.has(prop.name())) {
                    bringToTop(prop.name(), true);
                } else if (prop.initialValue() != null) {
                    pushPropertyValue(prop.initialValue());
                    sm.push("");
                } else {
                    emitOp(new PushOp(PushValue.of(0)));
                    sm.push("");
                }

                if ("bigint".equals(prop.type())) {
                    emitOp(new PushOp(PushValue.of(8)));
                    sm.push("");
                    emitOp(new OpcodeOp("OP_NUM2BIN"));
                    sm.pop();
                } else if ("boolean".equals(prop.type())) {
                    emitOp(new PushOp(PushValue.of(1)));
                    sm.push("");
                    emitOp(new OpcodeOp("OP_NUM2BIN"));
                    sm.pop();
                } else if ("ByteString".equals(prop.type())) {
                    emitPushDataEncode();
                }

                if (!first) {
                    sm.pop();
                    sm.pop();
                    emitOp(new OpcodeOp("OP_CAT"));
                    sm.push("");
                }
                first = false;
            }
            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        // ---------------- check_preimage (OP_PUSH_TX) ----------------

        void lowerCheckPreimage(String bindingName, String preimage, Integer sighashFlag,
                                int idx, Map<String, Integer> lastUses) {
            // OP_PUSH_TX: verify the pushed BIP-143 sighash preimage is bound to
            // the current spending transaction. The signature is DERIVED FROM THE
            // PREIMAGE ON CHAIN (Optimal OP_PUSH_TX): s = (hash256(preimage) + r)*
            // k⁻¹ mod n, with fixed nonce k and privkey d=1 (pubkey = G).
            // OP_CHECKSIG(sig, G) then passes iff hash256(preimage) equals the
            // node's real tx sighash — closing BUG-100. The unlocking script
            // pushes ONLY <preimage> (no witness signature). See
            // emitCheckPreimageBinding for the construction.

            // Emit OP_CODESEPARATOR so the scriptCode in the BIP-143 preimage is
            // only the code after this point (smaller preimage; required for
            // large scripts).
            emitOp(new OpcodeOp("OP_CODESEPARATOR"));

            // Bring the preimage to the top (kept for field extractors below).
            bringToTop(preimage, isLastUse(preimage, idx, lastUses));

            // Derive + verify the signature on-chain (single opaque raw_bytes
            // blob). For the default ALL|FORKID (sighashFlag null) the blob is
            // byte-identical to the pinned cross-tier constant; issue #123 lets a
            // method declare a different mode, which only changes the appended
            // sighash flag byte. Net stack effect is zero.
            emitCheckPreimageBinding(sighashFlag);

            // Preimage remains on top. Rename for field extractors.
            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        /**
         * Emit the on-chain preimage binding as one opaque raw_bytes op. Net
         * stack effect is 0 (preimage in → preimage out), declared as in=1/out=1
         * so the static analyzer keeps the depth consistent. The bytes are the
         * canonical construction shared byte-for-byte by all seven tiers for the
         * default ALL|FORKID mode; issue #123 swaps only the appended sighash
         * flag byte for a non-default declared mode.
         */
        void emitCheckPreimageBinding(Integer sighashFlag) {
            emitOp(new RawBytesOp(Emit.hexToBytes(checkPreimageBindingHex(sighashFlag)), 1, 1));
        }

        // ---------------- deserialize_state ----------------

        void lowerDeserializeState(String preimageRef, int idx, Map<String, Integer> lastUses) {
            List<AnfProperty> stateProps = new ArrayList<>();
            List<Integer> propSizes = new ArrayList<>();
            boolean hasVariableLength = false;
            for (AnfProperty p : properties) {
                if (p.readonly()) continue;
                stateProps.add(p);
                int sz;
                switch (p.type()) {
                    case "bigint", "RabinSig", "RabinPubKey" -> sz = 8;
                    case "boolean" -> sz = 1;
                    case "PubKey" -> sz = 33;
                    case "Addr", "Ripemd160" -> sz = 20;
                    case "Sha256" -> sz = 32;
                    case "Point", "P256Point" -> sz = 64;
                    case "P384Point" -> sz = 96;
                    case "ByteString", "Sig", "SigHashPreimage" -> {
                        sz = -1;
                        hasVariableLength = true;
                    }
                    default -> throw new RuntimeException("deserialize_state: unsupported type: " + p.type());
                }
                propSizes.add(sz);
            }

            if (stateProps.isEmpty()) return;

            bringToTop(preimageRef, isLastUse(preimageRef, idx, lastUses));

            // Skip first 104 bytes (header), drop prefix
            emitOp(new PushOp(PushValue.of(104)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new NipOp());
            sm.pop(); sm.pop();
            sm.push("");

            // Drop tail 44 bytes
            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitOp(new PushOp(PushValue.of(44)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SUB"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();

            // Drop amount (last 8 bytes)
            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitOp(new PushOp(PushValue.of(8)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SUB"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();

            if (!hasVariableLength) {
                int stateLen = 0;
                for (int s : propSizes) stateLen += s;
                // Extract last stateLen bytes
                emitOp(new OpcodeOp("OP_SIZE"));
                sm.push("");
                emitOp(new PushOp(PushValue.of(stateLen)));
                sm.push("");
                emitOp(new OpcodeOp("OP_SUB"));
                sm.pop(); sm.pop();
                sm.push("");
                emitOp(new OpcodeOp("OP_SPLIT"));
                sm.pop(); sm.pop();
                sm.push(""); sm.push("");
                emitOp(new NipOp());
                sm.pop(); sm.pop();
                sm.push("");

                splitFixedStateFields(stateProps, propSizes);
            } else if (!sm.has("_codePart")) {
                // Variable-length state but _codePart not available (terminal
                // method). Skip deserialization — the method body doesn't use
                // mutable state. Drop the varint+scriptCode from the stack.
                emitOp(new DropOp());
                sm.pop();
            } else {
                // Variable-length path: ByteString / Sig / SigHashPreimage
                // fields present. We need _codePart to compute the state
                // offset at runtime.
                //
                // After the steps above we have [varint || scriptCode] on the
                // stack and need to strip the BIP-143 scriptCode varint
                // prefix:
                //   length < 0xfd:        1 byte
                //   length <= 0xffff:     0xfd + 2 bytes LE  (3 bytes)
                //   length <= 0xffffffff: 0xfe + 4 bytes LE  (5 bytes)
                //   otherwise:            0xff + 8 bytes LE  (9 bytes)
                //
                // We must support all four shapes; stripping only 1- and
                // 3-byte varints corrupts state extraction for scripts whose
                // scriptCode exceeds 65,535 bytes (e.g. embedded BN254
                // verifiers) and surfaces as `Invalid OP_SPLIT range` on
                // regtest.
                emitOp(new PushOp(PushValue.of(1)));
                sm.push("");
                emitOp(new OpcodeOp("OP_SPLIT"));
                sm.pop(); sm.pop();
                sm.push(""); // firstByte
                sm.push(""); // rest
                emitOp(new SwapOp());
                sm.swap();
                // Zero-pad firstByte before BIN2NUM so 0xfd/0xfe/0xff aren't
                // interpreted as negative script numbers.
                emitOp(new PushOp(PushValue.ofHex("00")));
                sm.push("");
                emitOp(new OpcodeOp("OP_CAT"));
                sm.pop(); sm.pop();
                sm.push("");
                emitOp(new OpcodeOp("OP_BIN2NUM"));
                // Stack: [..., rest, fb_num]

                // IF fb_num < 253: 1-byte varint, drop fb_num.
                emitOp(new DupOp());
                sm.dup();
                emitOp(new PushOp(PushValue.of(253)));
                sm.push("");
                emitOp(new OpcodeOp("OP_LESSTHAN"));
                sm.pop(); sm.pop();
                sm.push("");
                emitOp(new OpcodeOp("OP_IF"));
                sm.pop();
                StackMap smAt1ByteIf = sm.clone0();
                emitOp(new DropOp());
                sm.pop();
                emitOp(new OpcodeOp("OP_ELSE"));
                sm.slots.clear();
                sm.slots.addAll(smAt1ByteIf.slots);
                // ELSE: fb_num >= 253. Check 0xfe (5-byte varint) next.
                emitOp(new DupOp());
                sm.dup();
                emitOp(new PushOp(PushValue.of(254)));
                sm.push("");
                emitOp(new OpcodeOp("OP_NUMEQUAL"));
                sm.pop(); sm.pop();
                sm.push("");
                emitOp(new OpcodeOp("OP_IF"));
                sm.pop();
                StackMap smAtFEIf = sm.clone0();
                // THEN: 5-byte varint (0xfe + 4 bytes LE).
                emitOp(new DropOp());
                sm.pop();
                emitDropMoreVarintBytes(4);
                emitOp(new OpcodeOp("OP_ELSE"));
                sm.slots.clear();
                sm.slots.addAll(smAtFEIf.slots);
                // ELSE: fb_num != 254. Check 0xff (9-byte varint) next.
                emitOp(new DupOp());
                sm.dup();
                emitOp(new PushOp(PushValue.of(255)));
                sm.push("");
                emitOp(new OpcodeOp("OP_NUMEQUAL"));
                sm.pop(); sm.pop();
                sm.push("");
                emitOp(new OpcodeOp("OP_IF"));
                sm.pop();
                StackMap smAtFFIf = sm.clone0();
                // THEN: 9-byte varint (0xff + 8 bytes LE).
                emitOp(new DropOp());
                sm.pop();
                emitDropMoreVarintBytes(8);
                emitOp(new OpcodeOp("OP_ELSE"));
                sm.slots.clear();
                sm.slots.addAll(smAtFFIf.slots);
                // ELSE: fb_num must be 253 (0xfd) — 3-byte varint.
                emitOp(new DropOp());
                sm.pop();
                emitDropMoreVarintBytes(2);
                emitOp(new OpcodeOp("OP_ENDIF"));
                emitOp(new OpcodeOp("OP_ENDIF"));
                emitOp(new OpcodeOp("OP_ENDIF"));
                // --- Stack: [..., scriptCode] ---

                // Compute skip = SIZE(_codePart) - codeSepIdx.
                bringToTop("_codePart", false); // PICK _codePart
                emitOp(new OpcodeOp("OP_SIZE"));
                sm.push("");
                emitOp(new NipOp());
                sm.pop(); sm.pop();
                sm.push("");
                // Push codeSepIndex — the emitter fills in the actual value
                emitOp(new PushCodeSepIndexOp());
                sm.push("");
                emitOp(new OpcodeOp("OP_SUB"));
                sm.pop(); sm.pop();
                sm.push("");
                // Stack: [..., scriptCode, skip]

                // Split scriptCode at skip to get state.
                emitOp(new OpcodeOp("OP_SPLIT"));
                sm.pop(); sm.pop();
                sm.push(""); // prefix (postSepCode + 0x6a)
                sm.push(""); // state
                emitOp(new NipOp());
                sm.pop(); sm.pop();
                sm.push(""); // state bytes on top

                // Parse state fields left-to-right.
                parseVariableLengthStateFields(stateProps, propSizes);
            }
            trackDepth();
        }

        // Drop `n` more varint bytes from the top-of-stack `rest`.
        // Stack in:  [..., rest]
        // Stack out: [..., rest_minus_n]
        private void emitDropMoreVarintBytes(int n) {
            emitOp(new PushOp(PushValue.of(n)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new NipOp());
            sm.pop(); sm.pop();
            sm.push("");
        }

        // Parse state fields left-to-right when at least one field is a
        // variable-length byte-string (ByteString, Sig, SigHashPreimage).
        // Mirrors {@code parseVariableLengthStateFields} in
        // {@code compilers/go/codegen/stack.go}.
        private void parseVariableLengthStateFields(List<AnfProperty> stateProps, List<Integer> sizes) {
            if (stateProps.size() == 1) {
                AnfProperty p = stateProps.get(0);
                if (isVariableLengthStateType(p.type())) {
                    // Single variable-length byte-string field: decode push-data
                    // prefix, drop trailing empty.
                    emitPushDataDecode(); // [..., data, remaining]
                    emitOp(new DropOp());
                    sm.pop();
                } else if (isNumericStateType(p.type())) {
                    emitOp(new OpcodeOp("OP_BIN2NUM"));
                }
                sm.pop();
                sm.push(p.name());
            } else {
                for (int i = 0; i < stateProps.size(); i++) {
                    AnfProperty p = stateProps.get(i);
                    if (i < stateProps.size() - 1) {
                        if (isVariableLengthStateType(p.type())) {
                            // Variable-length byte-string: decode push-data
                            // prefix, extract data.
                            emitPushDataDecode(); // [..., data, rest]
                            sm.pop(); sm.pop();
                            sm.push(p.name());
                            sm.push(""); // rest on top
                        } else {
                            int sz = sizes.get(i);
                            emitOp(new PushOp(PushValue.of(sz)));
                            sm.push("");
                            emitOp(new OpcodeOp("OP_SPLIT"));
                            sm.pop(); sm.pop();
                            sm.push(""); sm.push("");
                            emitOp(new SwapOp());
                            sm.swap();
                            if (isNumericStateType(p.type())) {
                                emitOp(new OpcodeOp("OP_BIN2NUM"));
                            }
                            emitOp(new SwapOp());
                            sm.swap();
                            sm.pop(); sm.pop();
                            sm.push(p.name());
                            sm.push("");
                        }
                    } else {
                        if (isVariableLengthStateType(p.type())) {
                            // Last variable-length byte-string: decode push-data
                            // prefix, drop trailing empty.
                            emitPushDataDecode(); // [..., data, remaining]
                            emitOp(new DropOp());
                            sm.pop();
                        } else if (isNumericStateType(p.type())) {
                            emitOp(new OpcodeOp("OP_BIN2NUM"));
                        }
                        sm.pop();
                        sm.push(p.name());
                    }
                }
            }
        }

        // emitPushDataDecode emits opcodes that decode a push-data-encoded
        // ByteString from the state bytes on top of the stack.
        // Expects stack: [..., state_bytes]
        // Leaves stack:  [..., data, remaining_state]
        // Mirrors {@code emitPushDataDecode} in
        // {@code compilers/go/codegen/stack.go}.
        private void emitPushDataDecode() {
            emitOp(new PushOp(PushValue.of(1)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            emitOp(new OpcodeOp("OP_BIN2NUM"));
            emitOp(new DupOp());
            sm.push("");
            emitOp(new PushOp(PushValue.of(76)));
            sm.push("");
            emitOp(new OpcodeOp("OP_LESSTHAN"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new OpcodeOp("OP_IF"));
            sm.pop();
            StackMap smAfterOuterIf = sm.clone0();

            // THEN: fb < 76 → direct length
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            StackMap smEndTarget = sm.clone0();

            emitOp(new OpcodeOp("OP_ELSE"));
            sm.slots.clear();
            sm.slots.addAll(smAfterOuterIf.slots);

            emitOp(new DupOp());
            sm.push("");
            emitOp(new PushOp(PushValue.of(77)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUMEQUAL"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new OpcodeOp("OP_IF"));
            sm.pop();
            StackMap smAfterInnerIf = sm.clone0();

            // THEN: fb == 77 → 2-byte LE length
            emitOp(new DropOp());
            sm.pop();
            emitOp(new PushOp(PushValue.of(2)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            emitOp(new OpcodeOp("OP_BIN2NUM"));
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");

            emitOp(new OpcodeOp("OP_ELSE"));
            sm.slots.clear();
            sm.slots.addAll(smAfterInnerIf.slots);

            // ELSE: fb == 76 → 1-byte length
            emitOp(new DropOp());
            sm.pop();
            emitOp(new PushOp(PushValue.of(1)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            emitOp(new OpcodeOp("OP_BIN2NUM"));
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");

            emitOp(new OpcodeOp("OP_ENDIF"));
            emitOp(new OpcodeOp("OP_ENDIF"));
            sm.slots.clear();
            sm.slots.addAll(smEndTarget.slots);
        }

        private void splitFixedStateFields(List<AnfProperty> stateProps, List<Integer> sizes) {
            if (stateProps.size() == 1) {
                AnfProperty p = stateProps.get(0);
                if (isNumericStateType(p.type())) {
                    emitOp(new OpcodeOp("OP_BIN2NUM"));
                }
                sm.pop();
                sm.push(p.name());
            } else {
                for (int i = 0; i < stateProps.size(); i++) {
                    AnfProperty p = stateProps.get(i);
                    int sz = sizes.get(i);
                    if (i < stateProps.size() - 1) {
                        emitOp(new PushOp(PushValue.of(sz)));
                        sm.push("");
                        emitOp(new OpcodeOp("OP_SPLIT"));
                        sm.pop(); sm.pop();
                        sm.push(""); sm.push("");
                        emitOp(new SwapOp());
                        sm.swap();
                        if (isNumericStateType(p.type())) {
                            emitOp(new OpcodeOp("OP_BIN2NUM"));
                        }
                        emitOp(new SwapOp());
                        sm.swap();
                        sm.pop(); sm.pop();
                        sm.push(p.name());
                        sm.push("");
                    } else {
                        if (isNumericStateType(p.type())) {
                            emitOp(new OpcodeOp("OP_BIN2NUM"));
                        }
                        sm.pop();
                        sm.push(p.name());
                    }
                }
            }
        }

        // ---------------- add_output / add_raw_output ----------------

        void lowerAddOutput(String bindingName, String satoshis, List<String> stateValues,
                            String preimage, int idx, Map<String, Integer> lastUses) {
            List<AnfProperty> stateProps = new ArrayList<>();
            for (AnfProperty p : properties) if (!p.readonly()) stateProps.add(p);
            List<String> outputOperands = new ArrayList<>();
            outputOperands.add(satoshis);
            outputOperands.addAll(stateValues);

            // Step 1: Bring _codePart to top (PICK)
            bringToTop("_codePart", false);

            // Step 2: Append OP_RETURN byte
            emitOp(new PushOp(PushValue.ofHex("6a")));
            sm.push("");
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            // Step 3: Serialise each state value
            int cnt = Math.min(stateValues.size(), stateProps.size());
            for (int i = 0; i < cnt; i++) {
                String valueRef = stateValues.get(i);
                AnfProperty prop = stateProps.get(i);
                bringToTop(valueRef, operandConsume(valueRef, outputOperands, idx, lastUses));
                if ("bigint".equals(prop.type())) {
                    emitOp(new PushOp(PushValue.of(8)));
                    sm.push("");
                    emitOp(new OpcodeOp("OP_NUM2BIN"));
                    sm.pop();
                } else if ("boolean".equals(prop.type())) {
                    emitOp(new PushOp(PushValue.of(1)));
                    sm.push("");
                    emitOp(new OpcodeOp("OP_NUM2BIN"));
                    sm.pop();
                } else if ("ByteString".equals(prop.type())) {
                    emitPushDataEncode();
                }
                sm.pop(); sm.pop();
                emitOp(new OpcodeOp("OP_CAT"));
                sm.push("");
            }

            // Step 4: Compute varint prefix
            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitVarintEncoding();

            // Step 5: SWAP CAT
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            // Step 6: Prepend satoshis as 8-byte LE
            bringToTop(satoshis, operandConsume(satoshis, outputOperands, idx, lastUses));
            emitOp(new PushOp(PushValue.of(8)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop();
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        void lowerAddRawOutput(String bindingName, String satoshis, String scriptBytes,
                               int idx, Map<String, Integer> lastUses) {
            bringToTop(scriptBytes, operandConsume(scriptBytes, List.of(satoshis, scriptBytes), idx, lastUses));

            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitVarintEncoding();

            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            bringToTop(satoshis, operandConsume(satoshis, List.of(satoshis, scriptBytes), idx, lastUses));
            emitOp(new PushOp(PushValue.of(8)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop();
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        // ---------------- buildChangeOutput ----------------

        void lowerBuildChangeOutput(String bindingName, List<String> args, int idx, Map<String, Integer> lastUses) {
            String pkh = args.get(0);
            String amount = args.get(1);

            emitOp(new PushOp(PushValue.ofHex("1976a914")));
            sm.push("");
            bringToTop(pkh, operandConsume(pkh, args, idx, lastUses));
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new PushOp(PushValue.ofHex("88ac")));
            sm.push("");
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            bringToTop(amount, operandConsume(amount, args, idx, lastUses));
            emitOp(new PushOp(PushValue.of(8)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop();
            emitOp(new SwapOp());
            sm.swap();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        // ---------------- computeStateOutput / computeStateOutputHash / extractOutputHash ----------------

        void lowerComputeStateOutputHash(String bindingName, List<String> args, int idx, Map<String, Integer> lastUses) {
            String preimage = args.get(0);
            String stateBytes = args.get(1);

            // stateBytes
            bringToTop(stateBytes, operandConsume(stateBytes, args, idx, lastUses));
            // preimage
            bringToTop(preimage, operandConsume(preimage, args, idx, lastUses));

            // Extract amount: last 52 bytes, take 8
            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitOp(new PushOp(PushValue.of(52)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SUB"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new NipOp());
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new PushOp(PushValue.of(8)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();

            // altstack
            emitOp(new OpcodeOp("OP_TOALTSTACK"));
            sm.pop();

            bringToTop("_codePart", false);

            emitOp(new PushOp(PushValue.ofHex("6a")));
            sm.push("");
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new SwapOp());
            sm.swap();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitVarintEncoding();

            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            emitOp(new OpcodeOp("OP_FROMALTSTACK"));
            sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new OpcodeOp("OP_HASH256"));
            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        void lowerComputeStateOutput(String bindingName, List<String> args, int idx, Map<String, Integer> lastUses) {
            String preimage = args.get(0);
            String stateBytes = args.get(1);
            String newAmount = args.get(2);

            // drop preimage
            bringToTop(preimage, operandConsume(preimage, args, idx, lastUses));
            emitOp(new DropOp());
            sm.pop();

            // newAmount -> 8-byte LE -> altstack
            bringToTop(newAmount, operandConsume(newAmount, args, idx, lastUses));
            emitOp(new PushOp(PushValue.of(8)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_TOALTSTACK"));
            sm.pop();

            bringToTop(stateBytes, operandConsume(stateBytes, args, idx, lastUses));
            bringToTop("_codePart", false);

            emitOp(new PushOp(PushValue.ofHex("6a")));
            sm.push("");
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new SwapOp());
            sm.swap();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitVarintEncoding();

            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            emitOp(new OpcodeOp("OP_FROMALTSTACK"));
            sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        void lowerExtractOutputHash(String bindingName, List<String> args, int idx, Map<String, Integer> lastUses) {
            // Direct port of the Python extractor — the entry consume (sm.pop
            // of the preimage) plus OP_SIZE's "double push" accounting keep
            // the stack map consistent with the physical stack.
            String preimage = args.get(0);
            bringToTop(preimage, isLastUse(preimage, idx, lastUses));
            sm.pop();
            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push(""); sm.push("");
            emitOp(new PushOp(PushValue.of(40)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SUB"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new NipOp());
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new PushOp(PushValue.of(32)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();
            // Rename the top result to the binding name (Python: sm.pop()+sm.push).
            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        // BIP-143 sighash preimage field extractors. Each takes the preimage
        // bytes on the stack and slices out the requested field. Direct port
        // of compilers/python/runar_compiler/codegen/stack.py:_lower_call's
        // extract* branches (lines 2451-2706 in Python).
        //
        // Field layout reference (BIP-143):
        //   0    : nVersion (4 bytes)
        //   4    : hashPrevouts (32 bytes)
        //   36   : hashSequence (32 bytes)
        //   68   : outpoint (36 bytes)
        //   104  : scriptCode (varint length + bytes)
        //   ...  : amount (8 bytes)
        //   ...  : nSequence (4 bytes)
        //   ...  : hashOutputs (32 bytes)
        //   end-8: nLocktime (4 bytes)
        //   end-4: sighashType (4 bytes)
        void lowerExtractor(String bindingName, String funcName, List<String> args,
                            int idx, Map<String, Integer> lastUses) {
            String arg = args.get(0);
            bringToTop(arg, isLastUse(arg, idx, lastUses));
            sm.pop();

            switch (funcName) {
                case "extractHashPrevouts":
                    emitAbsoluteSplit(4, 32, false);
                    break;
                case "extractHashSequence":
                    emitAbsoluteSplit(36, 32, false);
                    break;
                case "extractOutpoint":
                    emitAbsoluteSplit(68, 36, false);
                    break;
                case "extractSigHashType":
                    emitTrailingExtract(4, 0, true);
                    break;
                case "extractLocktime":
                    emitTrailingExtract(8, 4, true);
                    break;
                case "extractOutputHash":
                case "extractOutputs":
                    emitTrailingExtract(40, 32, false);
                    break;
                case "extractAmount":
                    emitTrailingExtract(52, 8, true);
                    break;
                case "extractSequence":
                    emitTrailingExtract(44, 4, true);
                    break;
                case "extractScriptCode":
                    emitScriptCodeExtract();
                    break;
                case "extractInputIndex":
                    emitInputIndexExtract();
                    break;
                default:
                    throw new RuntimeException("unknown extractor: " + funcName);
            }

            sm.pop();
            sm.push(bindingName);
            trackDepth();
        }

        /**
         * Slice the absolute byte range [start, start+length) out of the value
         * on top of the stack. Sequence: push start; OP_SPLIT; OP_NIP; push
         * length; OP_SPLIT; OP_DROP. The result is pushed under the empty
         * slot (caller renames to the binding).
         *
         * @param emitBin2Num always pass {@code false} here — absolute splits
         *                    keep the field as raw bytes; trailing extractors
         *                    that want a number should call {@link #emitTrailingExtract}.
         */
        private void emitAbsoluteSplit(int start, int length, boolean emitBin2Num) {
            emitOp(new PushOp(PushValue.of(start)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop();
            sm.push(""); sm.push("");
            emitOp(new NipOp());
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new PushOp(PushValue.of(length)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();
            if (emitBin2Num) {
                emitOp(new OpcodeOp("OP_BIN2NUM"));
            }
        }

        /**
         * Extract a field whose offset is end-relative: OP_SIZE push offset
         * OP_SUB OP_SPLIT OP_NIP, then optionally push length OP_SPLIT OP_DROP
         * to truncate, then optionally OP_BIN2NUM.
         */
        private void emitTrailingExtract(int trailingOffset, int innerLength, boolean emitBin2Num) {
            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push(""); sm.push("");
            emitOp(new PushOp(PushValue.of(trailingOffset)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SUB"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new NipOp());
            sm.pop(); sm.pop();
            sm.push("");

            if (innerLength > 0) {
                emitOp(new PushOp(PushValue.of(innerLength)));
                sm.push("");
                emitOp(new OpcodeOp("OP_SPLIT"));
                sm.pop(); sm.pop();
                sm.push(""); sm.push("");
                emitOp(new DropOp());
                sm.pop();
            }

            if (emitBin2Num) {
                emitOp(new OpcodeOp("OP_BIN2NUM"));
            }
        }

        private void emitScriptCodeExtract() {
            // skip first 104 bytes
            emitOp(new PushOp(PushValue.of(104)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop();
            sm.push(""); sm.push("");
            emitOp(new NipOp());
            sm.pop(); sm.pop();
            sm.push("");
            // trim trailing 52 bytes (amount + sequence + hashOutputs + locktime + sighashType)
            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitOp(new PushOp(PushValue.of(52)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SUB"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();
        }

        private void emitInputIndexExtract() {
            // skip first 100 bytes
            emitOp(new PushOp(PushValue.of(100)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop();
            sm.push(""); sm.push("");
            emitOp(new NipOp());
            sm.pop(); sm.pop();
            sm.push("");
            // take next 4 bytes
            emitOp(new PushOp(PushValue.of(4)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();
            emitOp(new OpcodeOp("OP_BIN2NUM"));
        }

        // ---------------- raw_script ----------------

        /**
         * Lower a raw_script ANF node to a single opaque RawBytesOp.
         *
         * <p>The bytes pass through verbatim — the emit pass writes them
         * as-is, and the peephole optimizer must not bridge across them.
         * Stack-tracker bookkeeping consumes {@code inArity} items and
         * pushes {@code outArity} items named after the binding so
         * downstream PICK/ROLL/DROP refer to the correct logical slot.
         */
        void lowerRawScript(String bindingName, String bytesHex, int inArity, int outArity) {
            if (sm.depth() < inArity) {
                throw new RuntimeException(String.format(
                    "raw_script binding '%s' requires %d stack items but only %d are present",
                    bindingName, inArity, sm.depth()
                ));
            }
            byte[] bytes;
            try {
                bytes = Emit.hexToBytes(bytesHex == null ? "" : bytesHex);
            } catch (RuntimeException e) {
                throw new RuntimeException(
                    "raw_script binding '" + bindingName + "' has invalid hex bytes: " + e.getMessage()
                );
            }
            emitOp(new RawBytesOp(bytes, inArity, outArity));
            for (int i = 0; i < inArity; i++) sm.pop();
            for (int i = 0; i < outArity; i++) {
                String slotName = bindingName;
                if (outArity != 1) slotName = bindingName + "." + i;
                sm.push(slotName);
            }
            trackDepth();
        }

        // ---------------- array_literal ----------------

        void lowerArrayLiteral(String bindingName, List<String> elements, int idx, Map<String, Integer> lastUses) {
            // Metadata-only. Array literals in Rúnar today only feed into
            // checkMultiSig. Pre-laying the elements onto the runtime stack
            // here would desync the stack-map from the runtime stack (the
            // map can only model one slot per binding, but an array binding
            // spans N runtime slots). lowerCheckMultiSig pulls each element
            // to TOS at the use site.
            arrayLengths.put(bindingName, elements.size());
            arrayElements.put(bindingName, new ArrayList<>(elements));
        }

        // ---------------- helpers: varint encoding, push-data encoding ----------------

        void emitVarintEncoding() {
            // Canonical Bitcoin varint over top-of-stack script length.
            // Matches the Python reference emit_varint_encoding; produces the
            // same 4-way conditional (1-byte / 0xfd+2 / 0xfe+4 / 0xff+8).
            emitOp(new DupOp());
            sm.dup();
            emitOp(new PushOp(PushValue.of(253)));
            sm.push("");
            emitOp(new OpcodeOp("OP_LESSTHAN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_IF"));
            sm.pop();
            StackMap snap1 = sm.clone0();
            emitNumToLowBytes(1);
            emitOp(new OpcodeOp("OP_ELSE"));
            sm.slots.clear();
            sm.slots.addAll(snap1.slots);

            emitOp(new DupOp());
            sm.dup();
            emitOp(new PushOp(PushValue.of(0x10000)));
            sm.push("");
            emitOp(new OpcodeOp("OP_LESSTHAN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_IF"));
            sm.pop();
            StackMap snap3 = sm.clone0();
            emitNumToLowBytes(2);
            emitPrefix(0xFD);
            emitOp(new OpcodeOp("OP_ELSE"));
            sm.slots.clear();
            sm.slots.addAll(snap3.slots);

            emitOp(new DupOp());
            sm.dup();
            emitOp(new PushOp(PushValue.of(0x100000000L)));
            sm.push("");
            emitOp(new OpcodeOp("OP_LESSTHAN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_IF"));
            sm.pop();
            StackMap snap5 = sm.clone0();
            emitNumToLowBytes(4);
            emitPrefix(0xFE);
            emitOp(new OpcodeOp("OP_ELSE"));
            sm.slots.clear();
            sm.slots.addAll(snap5.slots);

            emitNumToLowBytes(8);
            emitPrefix(0xFF);

            emitOp(new OpcodeOp("OP_ENDIF"));
            emitOp(new OpcodeOp("OP_ENDIF"));
            emitOp(new OpcodeOp("OP_ENDIF"));
        }

        private void emitNumToLowBytes(int n) {
            emitOp(new PushOp(PushValue.of(n + 1)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new PushOp(PushValue.of(n)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();
        }

        private void emitPrefix(int prefix) {
            emitOp(new PushOp(PushValue.ofHex(String.format("%02x", prefix & 0xff))));
            sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");
        }

        void emitPushDataEncode() {
            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitOp(new DupOp());
            sm.push("");
            emitOp(new PushOp(PushValue.of(76)));
            sm.push("");
            emitOp(new OpcodeOp("OP_LESSTHAN"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new OpcodeOp("OP_IF"));
            sm.pop();
            StackMap afterOuterIf = sm.clone0();

            // THEN: len <= 75
            emitOp(new PushOp(PushValue.of(2)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new PushOp(PushValue.of(1)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");
            StackMap endTarget = sm.clone0();

            emitOp(new OpcodeOp("OP_ELSE"));
            sm.slots.clear();
            sm.slots.addAll(afterOuterIf.slots);

            emitOp(new DupOp());
            sm.push("");
            emitOp(new PushOp(PushValue.of(256)));
            sm.push("");
            emitOp(new OpcodeOp("OP_LESSTHAN"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new OpcodeOp("OP_IF"));
            sm.pop();
            StackMap afterInnerIf = sm.clone0();

            // THEN: 76-255 -> 0x4c + 1-byte
            emitOp(new PushOp(PushValue.of(2)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new PushOp(PushValue.of(1)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();
            emitOp(new PushOp(PushValue.ofHex("4c")));
            sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            emitOp(new OpcodeOp("OP_ELSE"));
            sm.slots.clear();
            sm.slots.addAll(afterInnerIf.slots);

            // ELSE: >=256 -> 0x4d + 2-byte LE
            emitOp(new PushOp(PushValue.of(4)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new PushOp(PushValue.of(2)));
            sm.push("");
            emitOp(new OpcodeOp("OP_SPLIT"));
            sm.pop(); sm.pop();
            sm.push(""); sm.push("");
            emitOp(new DropOp());
            sm.pop();
            emitOp(new PushOp(PushValue.ofHex("4d")));
            sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");
            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            emitOp(new OpcodeOp("OP_ENDIF"));
            emitOp(new OpcodeOp("OP_ENDIF"));
            sm.slots.clear();
            sm.slots.addAll(endTarget.slots);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String bytesToHex(byte[] bs) {
        StringBuilder sb = new StringBuilder(bs.length * 2);
        for (byte b : bs) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
