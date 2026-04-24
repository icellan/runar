package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashMap;
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
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.NipOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PickOp;
import runar.compiler.ir.stack.PlaceholderOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
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
    }

    // ------------------------------------------------------------------
    // Last-use analysis
    // ------------------------------------------------------------------

    static Map<String, Integer> computeLastUses(List<AnfBinding> bindings) {
        Map<String, Integer> lastUse = new HashMap<>();
        for (int i = 0; i < bindings.size(); i++) {
            for (String r : collectRefs(bindings.get(i).value())) {
                lastUse.put(r, i);
            }
        }
        return lastUse;
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

        if (methodUsesCheckPreimage(method.body())) {
            // Implicit params pushed by the SDK before the developer's params.
            // Order matches the Python / Go / Rust references exactly:
            // _opPushTxSig is prepended first, then _codePart is prepended in
            // front of it, so the final paramNames layout is
            // [_codePart, _opPushTxSig, ...declared params...].
            paramNames.add(0, "_opPushTxSig");
            if (methodUsesCodePart(method.body())) {
                paramNames.add(0, "_codePart");
            }
        }

        LoweringContext ctx = new LoweringContext(paramNames, properties, privateMethods);
        ctx.lowerBindings(method.body(), method.isPublic());

        // Strip excess stack items left by deserialize_state on public methods.
        boolean hasDeserializeState = false;
        for (AnfBinding b : method.body()) {
            if (b.value() instanceof DeserializeState) { hasDeserializeState = true; break; }
        }
        if (method.isPublic() && hasDeserializeState && ctx.sm.depth() > 1) {
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

    private static boolean methodUsesCheckPreimage(List<AnfBinding> body) {
        for (AnfBinding b : body) {
            if (b.value() instanceof CheckPreimage) return true;
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

        LoweringContext(List<String> params, List<AnfProperty> properties) {
            this.sm = new StackMap(params);
            this.properties = properties;
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
            ops.add(op);
            trackDepth();
        }

        LoweringContext subContext() {
            LoweringContext c = new LoweringContext(null, properties);
            c.sm.slots.addAll(this.sm.slots);
            c.privateMethods = this.privateMethods;
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

        boolean isLastUse(String ref, int currentIndex, Map<String, Integer> lastUses) {
            Integer last = lastUses.get(ref);
            if (last == null) return true;
            return last <= currentIndex;
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
                if (b.value() instanceof Assert a && i == lastAssertIdx) {
                    lowerAssert(a.value(), i, lastUses, true);
                } else if (b.value() instanceof If iv && i == terminalIfIdx) {
                    lowerIf(b.name(), iv.cond(), iv.thenBranch(), iv.elseBranch(), i, lastUses, true);
                } else {
                    lowerBinding(b, i, lastUses);
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
                lowerIf(name, iv.cond(), iv.thenBranch(), iv.elseBranch(), idx, lastUses, false);
            } else if (v instanceof Loop l) {
                lowerLoop(name, l.count(), l.body(), l.iterVar());
            } else if (v instanceof Assert a) {
                lowerAssert(a.value(), idx, lastUses, false);
            } else if (v instanceof UpdateProp up) {
                lowerUpdateProp(up.name(), up.value(), idx, lastUses);
            } else if (v instanceof GetStateScript) {
                lowerGetStateScript(name);
            } else if (v instanceof CheckPreimage cp) {
                lowerCheckPreimage(name, cp.preimage(), idx, lastUses);
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
            }
        }

        // ---------------- load_param / load_prop / load_const ----------------

        void lowerLoadParam(String bindingName, String paramName, int idx, Map<String, Integer> lastUses) {
            if (sm.has(paramName)) {
                boolean isLast = isLastUse(paramName, idx, lastUses);
                bringToTop(paramName, isLast);
                sm.pop();
                sm.push(bindingName);
            } else {
                emitOp(new PushOp(PushValue.of(0)));
                sm.push(bindingName);
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
                int paramIndex = 0;
                for (AnfProperty p : properties) {
                    if (p.initialValue() != null) continue;
                    if (p.name().equals(propName)) break;
                    paramIndex++;
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
                    if (sm.has(refName)) {
                        boolean consume = Boolean.TRUE.equals(localBindings.get(refName))
                            && isLastUse(refName, idx, lastUses);
                        bringToTop(refName, consume);
                        sm.pop();
                        sm.push(bindingName);
                    } else {
                        emitOp(new PushOp(PushValue.of(0)));
                        sm.push(bindingName);
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
            bringToTop(left, isLastUse(left, idx, lastUses));
            bringToTop(right, isLastUse(right, idx, lastUses));
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

            // General builtin path
            for (String a : args) {
                bringToTop(a, isLastUse(a, idx, lastUses));
            }
            for (int i = 0; i < args.size(); i++) sm.pop();

            List<String> opcodes = BUILTIN_OPCODES.get(funcName);
            if (opcodes == null) {
                // Unknown function — emit a single placeholder push. Matches
                // Python's "emit 0" behaviour so the stack depth stays valid
                // but the resulting script won't verify. This is a safety net
                // for M5 scope: crypto builtins (EC, SHA-256, BN254, etc.)
                // land in M6.
                emitOp(new PushOp(PushValue.of(0)));
                sm.push(bindingName);
                return;
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

        // checkMultiSig: OP_0 + sigs + pks + OP_CHECKMULTISIG
        void lowerCheckMultiSig(String bindingName, List<String> args, int idx, Map<String, Integer> lastUses) {
            emitOp(new PushOp(PushValue.of(0)));
            sm.push("");
            bringToTop(args.get(0), isLastUse(args.get(0), idx, lastUses));
            bringToTop(args.get(1), isLastUse(args.get(1), idx, lastUses));
            sm.pop(); sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CHECKMULTISIG"));
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
                bringToTop(arg, isLastUse(arg, idx, lastUses));
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

        void lowerIf(String bindingName, String cond,
                     List<AnfBinding> thenB, List<AnfBinding> elseB,
                     int idx, Map<String, Integer> lastUses,
                     boolean terminalAssert) {
            bringToTop(cond, isLastUse(cond, idx, lastUses));
            sm.pop();

            Set<String> protectedRefs = new LinkedHashSet<>();
            for (Map.Entry<String, Integer> e : lastUses.entrySet()) {
                if (e.getValue() > idx && sm.has(e.getKey())) {
                    protectedRefs.add(e.getKey());
                }
            }

            Set<String> preIfNames = sm.namedSlots();

            LoweringContext thenCtx = subContext();
            thenCtx.outerProtectedRefs = protectedRefs;
            thenCtx.insideBranch = true;
            thenCtx.lowerBindings(thenB, terminalAssert);

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

            if (terminalAssert && elseCtx.sm.depth() > 1) {
                int excess = elseCtx.sm.depth() - 1;
                for (int i = 0; i < excess; i++) {
                    elseCtx.emitOp(new NipOp());
                    elseCtx.sm.removeAtDepth(1);
                }
            }

            // Phase 1: consumed-name analysis.
            Set<String> postThenNames = thenCtx.sm.namedSlots();
            List<String> consumedNames = new ArrayList<>();
            for (String n : preIfNames) {
                if (!postThenNames.contains(n) && elseCtx.sm.has(n)) consumedNames.add(n);
            }
            Set<String> postElseNames = elseCtx.sm.namedSlots();
            List<String> elseConsumedNames = new ArrayList<>();
            for (String n : preIfNames) {
                if (!postElseNames.contains(n) && thenCtx.sm.has(n)) elseConsumedNames.add(n);
            }

            if (!consumedNames.isEmpty()) {
                List<Integer> depths = new ArrayList<>();
                for (String n : consumedNames) depths.add(elseCtx.sm.findDepth(n));
                depths.sort((a, b) -> Integer.compare(b, a));
                for (int d : depths) dropAtDepth(elseCtx, d);
            }
            if (!elseConsumedNames.isEmpty()) {
                List<Integer> depths = new ArrayList<>();
                for (String n : elseConsumedNames) depths.add(thenCtx.sm.findDepth(n));
                depths.sort((a, b) -> Integer.compare(b, a));
                for (int d : depths) dropAtDepth(thenCtx, d);
            }

            // Phase 3: push placeholder if branches differ in depth.
            if (thenCtx.sm.depth() > elseCtx.sm.depth()) {
                String thenTop = thenCtx.sm.peekAtDepth(0);
                if (elseB.isEmpty() && thenTop != null && !thenTop.isEmpty() && elseCtx.sm.has(thenTop)) {
                    int varDepth = elseCtx.sm.findDepth(thenTop);
                    if (varDepth == 0) {
                        elseCtx.emitOp(new DupOp());
                    } else {
                        elseCtx.emitOp(new PushOp(PushValue.of(varDepth)));
                        elseCtx.sm.push("");
                        elseCtx.emitOp(new PickOp(varDepth));
                        elseCtx.sm.pop();
                    }
                    elseCtx.sm.push(thenTop);
                } else {
                    elseCtx.emitOp(new PushOp(PushValue.ofHex("")));
                    elseCtx.sm.push("");
                }
            } else if (elseCtx.sm.depth() > thenCtx.sm.depth()) {
                thenCtx.emitOp(new PushOp(PushValue.ofHex("")));
                thenCtx.sm.push("");
            }

            IfOp ifOp;
            if (!elseCtx.ops.isEmpty()) {
                ifOp = new IfOp(thenCtx.ops, elseCtx.ops);
            } else {
                ifOp = new IfOp(thenCtx.ops);
            }
            emitOp(ifOp);

            // Reconcile parent stackMap with consumed names in both branches.
            Set<String> postBranchNames = thenCtx.sm.namedSlots();
            List<String> toRemove = new ArrayList<>();
            for (String n : preIfNames) {
                if (!postBranchNames.contains(n) && sm.has(n)) toRemove.add(n);
            }
            for (String n : toRemove) {
                int d = sm.findDepth(n);
                sm.removeAtDepth(d);
            }

            // If expression may produce a result value on top
            if (thenCtx.sm.depth() > sm.depth()) {
                String thenTop = thenCtx.sm.peekAtDepth(0);
                String elseTop = elseCtx.sm.depth() > 0 ? elseCtx.sm.peekAtDepth(0) : "";
                boolean isProperty = false;
                for (AnfProperty p : properties) if (p.name().equals(thenTop)) { isProperty = true; break; }
                if (isProperty && thenTop != null && !thenTop.isEmpty() && thenTop.equals(elseTop)
                    && !thenTop.equals(bindingName) && sm.has(thenTop)) {
                    sm.push(thenTop);
                    rebalanceDuplicate(thenTop);
                } else if (thenTop != null && !thenTop.isEmpty() && !isProperty
                    && elseB.isEmpty() && !thenTop.equals(bindingName) && sm.has(thenTop)) {
                    sm.push(thenTop);
                    rebalanceDuplicate(thenTop);
                } else {
                    sm.push(bindingName);
                }
            } else if (elseCtx.sm.depth() > sm.depth()) {
                sm.push(bindingName);
            }

            trackDepth();

            if (thenCtx.maxDepth > maxDepth) maxDepth = thenCtx.maxDepth;
            if (elseCtx.maxDepth > maxDepth) maxDepth = elseCtx.maxDepth;
        }

        private void rebalanceDuplicate(String name) {
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
                    break;
                }
            }
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

        void lowerLoop(String bindingName, int count, List<AnfBinding> body, String iterVar) {
            Map<String, Boolean> bodyNames = new HashMap<>();
            for (AnfBinding b : body) bodyNames.put(b.name(), true);

            Set<String> outerRefs = new LinkedHashSet<>();
            for (AnfBinding b : body) {
                if (b.value() instanceof LoadParam lp && !lp.name().equals(iterVar)) {
                    outerRefs.add(lp.name());
                }
                if (b.value() instanceof LoadConst lc && lc.value() instanceof BytesConst bc
                    && bc.hex() != null && bc.hex().length() > 5 && bc.hex().startsWith("@ref:")) {
                    String target = bc.hex().substring(5);
                    if (!bodyNames.containsKey(target)) outerRefs.add(target);
                }
            }

            Map<String, Boolean> prevLocal = localBindings;
            Map<String, Boolean> newLocal = new HashMap<>(prevLocal);
            newLocal.putAll(bodyNames);
            localBindings = newLocal;

            for (int i = 0; i < count; i++) {
                emitOp(new PushOp(PushValue.of(i)));
                sm.push(iterVar);
                Map<String, Integer> lastUses = computeLastUses(body);
                if (i < count - 1) {
                    for (String ref : outerRefs) lastUses.put(ref, body.size());
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

        void lowerCheckPreimage(String bindingName, String preimage, int idx, Map<String, Integer> lastUses) {
            emitOp(new OpcodeOp("OP_CODESEPARATOR"));

            bringToTop(preimage, isLastUse(preimage, idx, lastUses));
            bringToTop("_opPushTxSig", true);

            byte[] G = new byte[] {
                0x02, 0x79, (byte)0xBE, 0x66, 0x7E, (byte)0xF9, (byte)0xDC, (byte)0xBB,
                (byte)0xAC, 0x55, (byte)0xA0, 0x62, (byte)0x95, (byte)0xCE, (byte)0x87, 0x0B,
                0x07, 0x02, (byte)0x9B, (byte)0xFC, (byte)0xDB, 0x2D, (byte)0xCE, 0x28,
                (byte)0xD9, 0x59, (byte)0xF2, (byte)0x81, 0x5B, 0x16, (byte)0xF8, 0x17,
                (byte)0x98
            };
            emitOp(new PushOp(PushValue.ofHex(bytesToHex(G))));
            sm.push("");

            emitOp(new OpcodeOp("OP_CHECKSIGVERIFY"));
            sm.pop();
            sm.pop();
            sm.pop();
            sm.push(bindingName);
            trackDepth();
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
            } else {
                // Variable-length state: full support lives in M6's crypto
                // codegen. For M5 we throw a clear error so M4-era fixtures
                // exercising only fixed-width state still pass.
                throw new RuntimeException(
                    "deserialize_state: variable-length state fields are not yet supported "
                    + "(M6 will add the full varint-stripping codegen)");
            }
            trackDepth();
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
                bringToTop(valueRef, isLastUse(valueRef, idx, lastUses));
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
            bringToTop(satoshis, isLastUse(satoshis, idx, lastUses));
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
            bringToTop(scriptBytes, isLastUse(scriptBytes, idx, lastUses));

            emitOp(new OpcodeOp("OP_SIZE"));
            sm.push("");
            emitVarintEncoding();

            emitOp(new SwapOp());
            sm.swap();
            sm.pop(); sm.pop();
            emitOp(new OpcodeOp("OP_CAT"));
            sm.push("");

            bringToTop(satoshis, isLastUse(satoshis, idx, lastUses));
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
            bringToTop(pkh, isLastUse(pkh, idx, lastUses));
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            emitOp(new PushOp(PushValue.ofHex("88ac")));
            sm.push("");
            emitOp(new OpcodeOp("OP_CAT"));
            sm.pop(); sm.pop();
            sm.push("");

            bringToTop(amount, isLastUse(amount, idx, lastUses));
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
            bringToTop(stateBytes, isLastUse(stateBytes, idx, lastUses));
            // preimage
            bringToTop(preimage, isLastUse(preimage, idx, lastUses));

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
            bringToTop(preimage, isLastUse(preimage, idx, lastUses));
            emitOp(new DropOp());
            sm.pop();

            // newAmount -> 8-byte LE -> altstack
            bringToTop(newAmount, isLastUse(newAmount, idx, lastUses));
            emitOp(new PushOp(PushValue.of(8)));
            sm.push("");
            emitOp(new OpcodeOp("OP_NUM2BIN"));
            sm.pop(); sm.pop();
            sm.push("");
            emitOp(new OpcodeOp("OP_TOALTSTACK"));
            sm.pop();

            bringToTop(stateBytes, isLastUse(stateBytes, idx, lastUses));
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

        void lowerExtractor(String bindingName, String funcName, List<String> args,
                            int idx, Map<String, Integer> lastUses) {
            // A minimal subset of preimage extractors — full coverage lives in M6.
            String arg = args.get(0);
            bringToTop(arg, isLastUse(arg, idx, lastUses));
            sm.pop();
            // The only one we need here is a generic "extract N-byte field".
            // Emit a no-op that keeps the preimage on the stack so the binding
            // name resolves; actual field extraction lowering lives in M6.
            sm.push(bindingName);
        }

        // ---------------- array_literal ----------------

        void lowerArrayLiteral(String bindingName, List<String> elements, int idx, Map<String, Integer> lastUses) {
            for (String el : elements) {
                bringToTop(el, isLastUse(el, idx, lastUses));
                sm.pop();
                sm.push("");
            }
            if (!elements.isEmpty()) sm.pop();
            sm.push(bindingName);
            trackDepth();
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
