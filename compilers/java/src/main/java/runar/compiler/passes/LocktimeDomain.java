package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParamNode;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * D26: a block-height locktime gate must pin the locktime domain. Port of
 * {@code packages/runar-compiler/src/passes/locktime-domain.ts} (see its header
 * for the full rationale and the exact GATE / PIN / DERIVED definitions).
 *
 * <p>Consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so
 * {@code extractLocktime(p) >= H} for a height H passes for any such locktime.
 * Per path (D18's path walk, two bits: gate seen G, pin seen P), every path
 * through a public method that carries a lower-bound gate on a locktime read
 * must also carry an asserted domain pin. The source rule is reported by
 * {@link Typecheck}; {@link #checkIr} re-derives it from the ANF on --ir input.
 */
public final class LocktimeDomain {

    private LocktimeDomain() {}

    /** D26: the shared error text. */
    public static String locktimeDomainMessage(String method) {
        return "method '" + method + "' compares extractLocktime against a lower bound without pinning the locktime domain: "
            + "consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so on that path any such locktime "
            + "passes a block-height gate at once. On every path that compares, assert(extractLocktime(preimage) < "
            + "500000000n) for a block-height gate, or assert(extractLocktime(preimage) >= 500000000n) for a timestamp gate";
    }

    /** The first nLockTime value consensus reads as a Unix timestamp. */
    static final BigInteger LOCKTIME_THRESHOLD = BigInteger.valueOf(500000000L);

    // ------------------------------------------------------------------
    // Path states: G (gate seen) and P (pin seen), as a 4-bit mask of states.
    // ------------------------------------------------------------------

    static final int G = 1;
    static final int P = 2;
    static final int ZERO = 1;

    static int orAll(int states, int bits) {
        int out = 0;
        for (int x = 0; x < 4; x++) if ((states >> x & 1) != 0) out |= 1 << (x | bits);
        return out;
    }

    static int compose(int a, int b) {
        int out = 0;
        for (int y = 0; y < 4; y++) if ((b >> y & 1) != 0) out |= orAll(a, y);
        return out;
    }

    /** Some live path carries a gate (G) and no pin (not P): state 1. */
    static boolean unpinned(int states) {
        return (states & (1 << G)) != 0;
    }

    // ------------------------------------------------------------------
    // Classification
    // ------------------------------------------------------------------

    enum Cls { NONE, GATE, PIN }

    private static String flip(String op) {
        switch (op) {
            case "<": return ">";
            case "<=": return ">=";
            case ">": return "<";
            default: return "<=";
        }
    }

    private static boolean isCmp(String op) {
        return op.equals("<") || op.equals("<=") || op.equals(">") || op.equals(">=");
    }

    /** Classify {@code lt <op> other} (the read on the left); other is null when not a bigint literal. */
    private static Cls classify(String op, BigInteger other) {
        if (op.equals(">=") || op.equals(">")) {
            // `>= 0` is vacuous (every locktime passes it): no gate. Only literal 0:
            // a negative bound is a negation in source but may be a literal in IR.
            if (op.equals(">=") && other != null && other.signum() == 0) return Cls.NONE;
            boolean ts = other != null && (op.equals(">=")
                ? other.compareTo(LOCKTIME_THRESHOLD) >= 0
                : other.compareTo(LOCKTIME_THRESHOLD.subtract(BigInteger.ONE)) >= 0);
            return ts ? Cls.PIN : Cls.GATE;
        }
        if (other == null) return Cls.NONE;
        boolean height = op.equals("<")
            ? other.signum() > 0 && other.compareTo(LOCKTIME_THRESHOLD) <= 0
            : other.signum() >= 0 && other.compareTo(LOCKTIME_THRESHOLD) < 0;
        return height ? Cls.PIN : Cls.NONE;
    }

    /** Taint level: not a locktime read / a direct read / derived from one. */
    static final int NONE = 0;
    static final int DIRECT = 1;
    static final int DERIVED = 2;

    private static final Set<String> PROPAGATE = Set.of("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>");
    private static final Set<String> PROPAGATE_UNARY = Set.of("-", "~");

    private static Cls side(int lv, String op, BigInteger other) {
        if (lv == DIRECT) return classify(op, other);
        if (lv == DERIVED) return op.equals(">=") || op.equals(">") ? Cls.GATE : Cls.NONE;
        return Cls.NONE;
    }

    /** Each tainted side is read as the left one; a gate on either side wins over a pin. */
    private static Cls classifyCompare(String op, int lLevel, BigInteger lLit, int rLevel, BigInteger rLit) {
        if (!isCmp(op)) return Cls.NONE;
        Cls a = side(lLevel, op, rLit);
        Cls b = side(rLevel, flip(op), lLit);
        if (a == Cls.GATE || b == Cls.GATE) return Cls.GATE;
        return a == Cls.PIN || b == Cls.PIN ? Cls.PIN : Cls.NONE;
    }

    /** A binding predicate over a name set (tainted / direct). */
    private interface Pred<B> {
        boolean test(B b, Set<String> names);
    }

    /**
     * Least fixpoint for the tainted set, then greatest fixpoint (within it)
     * for the names all of whose bindings are direct reads. Order-blind.
     */
    private static <B> Map<String, Integer> solveTaint(List<String> names, List<B> binds, Pred<B> tainted, Pred<B> direct) {
        Set<String> t = new HashSet<>();
        for (boolean changed = true; changed; ) {
            changed = false;
            for (int i = 0; i < names.size(); i++) {
                if (!t.contains(names.get(i)) && tainted.test(binds.get(i), t)) {
                    t.add(names.get(i));
                    changed = true;
                }
            }
        }
        Set<String> d = new HashSet<>(t);
        for (boolean changed = true; changed; ) {
            changed = false;
            for (int i = 0; i < names.size(); i++) {
                if (d.contains(names.get(i)) && !direct.test(binds.get(i), d)) {
                    d.remove(names.get(i));
                    changed = true;
                }
            }
        }
        Map<String, Integer> out = new HashMap<>();
        for (String n : t) out.put(n, d.contains(n) ? DIRECT : DERIVED);
        return out;
    }

    // ------------------------------------------------------------------
    // Source path
    // ------------------------------------------------------------------

    private static boolean isCallTo(Expression e, String name) {
        return e instanceof CallExpr c && c.callee() instanceof Identifier id && id.name().equals(name);
    }

    /**
     * A D26 locktime read. currentBlockHeight() is not one: it asserts its own
     * value < 500000000 at the call (AnfLower), so it is a height by
     * construction. Mirrors locktime-domain.ts.
     */
    private static boolean isLocktimeRead(Expression e) {
        return isCallTo(e, "extractLocktime");
    }

    /** D26 prefilter: some method reads the locktime (extractLocktime). */
    static boolean contractReadsLocktime(ContractNode contract) {
        List<Object> roots = new ArrayList<>();
        for (MethodNode m : contract.methods()) roots.addAll(m.body());
        return containsExpr(roots, LocktimeDomain::isLocktimeRead);
    }

    /** The shared error text for a currentBlockHeight() compare against a timestamp-domain bound. */
    static String currentBlockHeightTimestampMessage(String method) {
        return "method '" + method + "' compares currentBlockHeight() against a Unix-timestamp bound: currentBlockHeight() asserts "
            + "its value is below 500000000 (a block height), so this compare can never pass and an output gated on it "
            + "could never be spent. Use extractLocktime(this.txPreimage) for a timestamp gate";
    }

    /**
     * True iff {@code method} contains, anywhere, a lower-bound compare of a
     * direct currentBlockHeight() call (or a local every binding of which is
     * one) against a timestamp-domain bigint
     * literal ({@code >= N}, N >= 500000000; {@code > N}, N >= 499999999; or
     * reversed). currentBlockHeight() asserts its value is below 500000000,
     * so such a compare can never pass. Mirrors
     * comparesCurrentBlockHeightToTimestamp in locktime-domain.ts.
     */
    static boolean comparesCurrentBlockHeightToTimestamp(MethodNode method) {
        // Locals bound only to currentBlockHeight() (every declaration/assignment).
        Map<String, Boolean> cbhOnly = new HashMap<>();
        ArrayDeque<List<Statement>> work = new ArrayDeque<>();
        work.add(method.body());
        while (!work.isEmpty()) {
            for (Statement st : work.poll()) {
                if (st instanceof VariableDeclStatement vd) {
                    cbhOnly.merge(vd.name(), isCallTo(vd.init(), "currentBlockHeight"), Boolean::logicalAnd);
                } else if (st instanceof AssignmentStatement a && a.target() instanceof Identifier id) {
                    cbhOnly.merge(id.name(), isCallTo(a.value(), "currentBlockHeight"), Boolean::logicalAnd);
                } else if (st instanceof IfStatement i) {
                    work.add(i.thenBody());
                    if (i.elseBody() != null) work.add(i.elseBody());
                } else if (st instanceof ForStatement f) {
                    if (f.init() != null) work.add(List.of(f.init()));
                    work.add(f.body());
                }
            }
        }
        java.util.function.Predicate<Expression> isCbh = x -> isCallTo(x, "currentBlockHeight")
            || (x instanceof Identifier id && cbhOnly.getOrDefault(id.name(), false));
        return containsExpr(new ArrayList<>(method.body()), e -> {
            if (!(e instanceof BinaryExpr b)) return false;
            String op = b.op().canonical();
            if (!isCmp(op)) return false;
            if (isCbh.test(b.left()) && (op.equals(">=") || op.equals(">"))
                && classify(op, literalOf(b.right())) == Cls.PIN) return true;
            String f = flip(op);
            return isCbh.test(b.right()) && (f.equals(">=") || f.equals(">"))
                && classify(f, literalOf(b.left())) == Cls.PIN;
        });
    }

    /** True iff some expression reachable from {@code roots} (statements / expressions) satisfies {@code pred}. */
    private static boolean containsExpr(List<Object> roots, java.util.function.Predicate<Expression> pred) {
        ArrayDeque<Object> work = new ArrayDeque<>();
        for (Object r : roots) if (r != null) work.push(r);
        while (!work.isEmpty()) {
            Object o = work.pop();
            if (o instanceof Expression e) {
                if (pred.test(e)) return true;
                if (e instanceof CallExpr c) {
                    if (c.callee() != null) work.push(c.callee());
                    work.addAll(c.args());
                } else if (e instanceof BinaryExpr b) {
                    work.push(b.left());
                    work.push(b.right());
                } else if (e instanceof UnaryExpr u) {
                    work.push(u.operand());
                } else if (e instanceof TernaryExpr t) {
                    work.push(t.condition());
                    work.push(t.consequent());
                    work.push(t.alternate());
                } else if (e instanceof IndexAccessExpr ia) {
                    work.push(ia.object());
                    work.push(ia.index());
                } else if (e instanceof MemberExpr me) {
                    work.push(me.object());
                } else if (e instanceof IncrementExpr ie) {
                    work.push(ie.operand());
                } else if (e instanceof DecrementExpr de) {
                    work.push(de.operand());
                } else if (e instanceof ArrayLiteralExpr al) {
                    work.addAll(al.elements());
                }
            } else if (o instanceof AssignmentStatement a) {
                pushNonNull(work, a.target());
                pushNonNull(work, a.value());
            } else if (o instanceof ExpressionStatement es) {
                pushNonNull(work, es.expression());
            } else if (o instanceof VariableDeclStatement vd) {
                pushNonNull(work, vd.init());
            } else if (o instanceof ReturnStatement r) {
                pushNonNull(work, r.value());
            } else if (o instanceof IfStatement i) {
                pushNonNull(work, i.condition());
                work.addAll(i.thenBody());
                if (i.elseBody() != null) work.addAll(i.elseBody());
            } else if (o instanceof ForStatement f) {
                pushNonNull(work, f.init());
                pushNonNull(work, f.condition());
                pushNonNull(work, f.update());
                work.addAll(f.body());
            }
            work.removeIf(java.util.Objects::isNull);
        }
        return false;
    }

    private static void pushNonNull(ArrayDeque<Object> work, Object o) {
        if (o != null) work.push(o);
    }

    /** Taint level of a source expression, given the taint of the names in scope. */
    private static int exprLevel(Expression e, Map<String, Integer> names) {
        if (e == null) return NONE;
        if (isLocktimeRead(e)) return DIRECT;
        if (e instanceof Identifier id) return names.getOrDefault(id.name(), NONE);
        if (e instanceof BinaryExpr b) {
            return PROPAGATE.contains(b.op().canonical())
                && (exprLevel(b.left(), names) != NONE || exprLevel(b.right(), names) != NONE) ? DERIVED : NONE;
        }
        if (e instanceof UnaryExpr u) {
            return PROPAGATE_UNARY.contains(u.op().canonical()) && exprLevel(u.operand(), names) != NONE ? DERIVED : NONE;
        }
        if (e instanceof TernaryExpr t) {
            return exprLevel(t.consequent(), names) != NONE || exprLevel(t.alternate(), names) != NONE ? DERIVED : NONE;
        }
        if (e instanceof CallExpr c) {
            // A builtin (identifier callee); a helper's return is not followed.
            if (!(c.callee() instanceof Identifier)) return NONE;
            for (Expression a : c.args()) if (exprLevel(a, names) != NONE) return DERIVED;
            return NONE;
        }
        return NONE;
    }

    private static BigInteger literalOf(Expression e) {
        return e instanceof BigIntLiteral bl ? bl.value() : null;
    }

    /**
     * Taint of the method's locals and parameters, from every binding in the
     * body (declaration or assignment, anywhere) plus one binding per tainted
     * parameter (the level its call passes it). Order-blind on purpose.
     */
    private static Map<String, Integer> collectLocals(List<Statement> body, Map<String, Integer> params) {
        List<String> names = new ArrayList<>();
        List<Object> binds = new ArrayList<>();
        for (Map.Entry<String, Integer> p : params.entrySet()) {
            names.add(p.getKey());
            binds.add(p.getValue());
        }
        ArrayDeque<List<Statement>> work = new ArrayDeque<>();
        work.add(body);
        while (!work.isEmpty()) {
            for (Statement st : work.poll()) {
                if (st instanceof VariableDeclStatement vd) {
                    names.add(vd.name());
                    binds.add(vd.init());
                } else if (st instanceof AssignmentStatement a && a.target() instanceof Identifier id) {
                    names.add(id.name());
                    binds.add(a.value());
                } else if (st instanceof IfStatement i) {
                    work.add(i.thenBody());
                    if (i.elseBody() != null) work.add(i.elseBody());
                } else if (st instanceof ForStatement f) {
                    if (f.init() != null) work.add(List.of(f.init()));
                    work.add(f.body());
                }
            }
        }
        return solveTaint(
            names,
            binds,
            (b, t) -> {
                if (b instanceof Integer lv) return lv != NONE;
                Map<String, Integer> asMap = new HashMap<>();
                for (String n : t) asMap.put(n, DIRECT);
                return exprLevel((Expression) b, asMap) != NONE;
            },
            (b, d) -> {
                if (b instanceof Integer lv) return lv == DIRECT;
                Expression e = (Expression) b;
                return isLocktimeRead(e) || (e instanceof Identifier id && d.contains(id.name()));
            });
    }

    /** D26 (source path): true iff some path through public {@code method} carries an unpinned gate. */
    static boolean hasUnpinnedLocktimeGate(ContractNode contract, MethodNode method) {
        return unpinned(new SourceGates(contract).exits(method, new HashMap<>()));
    }

    private static final class SourceGates {
        private record Flow(int live, int returned) {}

        private final Map<String, MethodNode> privates = new HashMap<>();
        /** Helper exits, by helper name and the taint level of each argument. */
        private final Map<String, Integer> helperExits = new HashMap<>();
        private final Set<String> inProgress = new HashSet<>();
        /** Taint level of the locals and parameters of the method being walked. */
        private Map<String, Integer> locals = new HashMap<>();

        SourceGates(ContractNode contract) {
            for (MethodNode m : contract.methods()) {
                if (m.visibility() == Visibility.PRIVATE) privates.put(m.name(), m);
            }
        }

        int exits(MethodNode method, Map<String, Integer> params) {
            Map<String, Integer> saved = locals;
            locals = collectLocals(method.body(), params);
            Flow f = stmts(method.body(), ZERO);
            locals = saved;
            return f.live() | f.returned();
        }

        private int level(Expression e) {
            return exprLevel(e, locals);
        }

        private Cls compare(Expression e) {
            if (!(e instanceof BinaryExpr b)) return Cls.NONE;
            return classifyCompare(b.op().canonical(), level(b.left()), literalOf(b.left()), level(b.right()), literalOf(b.right()));
        }

        private boolean assertedPin(Expression e) {
            if (compare(e) == Cls.PIN) return true;
            if (e instanceof BinaryExpr b && b.op() == Expression.BinaryOp.AND) {
                return assertedPin(b.left()) || assertedPin(b.right());
            }
            return false;
        }

        private Flow stmts(List<Statement> list, int states) {
            int live = states;
            int returned = 0;
            if (list == null) return new Flow(live, 0);
            for (Statement st : list) {
                if (live == 0) break;
                Flow f = stmt(st, live);
                returned |= f.returned();
                live = f.live();
            }
            return new Flow(live, returned);
        }

        private Flow stmt(Statement st, int states) {
            if (st == null) return new Flow(states, 0);
            if (st instanceof AssignmentStatement a) return new Flow(expr(a.value(), expr(a.target(), states)), 0);
            if (st instanceof ExpressionStatement es) return new Flow(expr(es.expression(), states), 0);
            if (st instanceof VariableDeclStatement vd) return new Flow(expr(vd.init(), states), 0);
            if (st instanceof ReturnStatement r) {
                return new Flow(0, r.value() != null ? expr(r.value(), states) : states);
            }
            if (st instanceof IfStatement i) {
                int c = expr(i.condition(), states);
                Flow t = stmts(i.thenBody(), c);
                Flow e = i.elseBody() != null ? stmts(i.elseBody(), c) : new Flow(c, 0);
                return new Flow(t.live() | e.live(), t.returned() | e.returned());
            }
            if (st instanceof ForStatement f) {
                Flow init = f.init() != null ? stmt(f.init(), states) : new Flow(states, 0);
                int c = expr(f.condition(), init.live());
                Flow body = stmts(f.body(), c);
                Flow upd = f.update() != null ? stmt(f.update(), body.live()) : new Flow(body.live(), 0);
                return new Flow(c | upd.live(), init.returned() | body.returned() | upd.returned());
            }
            return new Flow(states, 0);
        }

        private int expr(Expression e, int states) {
            if (e == null) return states;
            if (e instanceof CallExpr call) {
                int s = states;
                if (call.callee() != null && !(call.callee() instanceof Identifier)) s = expr(call.callee(), s);
                for (Expression a : call.args()) s = expr(a, s);
                // The Java surface keeps assertThat(...) as its own callee (see PreimageChecked).
                if ((isCallTo(e, "assert") || isCallTo(e, "assertThat"))
                        && !call.args().isEmpty() && assertedPin(call.args().get(0))) {
                    return orAll(s, P);
                }
                String name = call.callee() instanceof PropertyAccessExpr pa ? pa.property()
                    : call.callee() instanceof MemberExpr me ? me.property() : null;
                MethodNode helper = name != null ? privates.get(name) : null;
                if (helper == null) return s;
                int[] levels = new int[call.args().size()];
                for (int i = 0; i < levels.length; i++) levels[i] = level(call.args().get(i));
                return compose(s, helper(helper, levels));
            }
            if (e instanceof BinaryExpr b) {
                int s = expr(b.right(), expr(b.left(), states));
                return compare(e) == Cls.GATE ? orAll(s, G) : s;
            }
            if (e instanceof UnaryExpr u) return expr(u.operand(), states);
            if (e instanceof TernaryExpr t) {
                int c = expr(t.condition(), states);
                return expr(t.consequent(), c) | expr(t.alternate(), c);
            }
            if (e instanceof IndexAccessExpr ia) return expr(ia.index(), expr(ia.object(), states));
            if (e instanceof MemberExpr me) return expr(me.object(), states);
            if (e instanceof IncrementExpr ie) return expr(ie.operand(), states);
            if (e instanceof DecrementExpr de) return expr(de.operand(), states);
            if (e instanceof ArrayLiteralExpr al) {
                int s = states;
                for (Expression el : al.elements()) s = expr(el, s);
                return s;
            }
            return states;
        }

        private int helper(MethodNode m, int[] argLevels) {
            Map<String, Integer> params = new HashMap<>();
            StringBuilder key = new StringBuilder(m.name()).append('|');
            List<ParamNode> ps = m.params();
            for (int i = 0; i < ps.size(); i++) {
                int lv = i < argLevels.length ? argLevels[i] : NONE;
                if (lv != NONE) params.put(ps.get(i).name(), lv);
                if (i > 0) key.append(',');
                key.append(lv);
            }
            Integer cached = helperExits.get(key.toString());
            if (cached != null) return cached;
            // Recursion is refused by the validator; a cycle contributes nothing.
            if (inProgress.contains(m.name())) return ZERO;
            inProgress.add(m.name());
            int ex = exits(m, params);
            inProgress.remove(m.name());
            helperExits.put(key.toString(), ex);
            return ex;
        }
    }

    // ------------------------------------------------------------------
    // --ir path (port of assertIrLocktimeDomain)
    // ------------------------------------------------------------------

    private static String refOf(AnfValue v) {
        if (v instanceof LoadConst lc && lc.value() instanceof BytesConst bc && bc.hex() != null && bc.hex().startsWith("@ref:")) {
            return bc.hex().substring(5);
        }
        return null;
    }

    /**
     * {@code bs[i]} is the ANF image of {@code currentBlockHeight()}
     * ({@link AnfLower}): a {@code call extractLocktime} followed in the same
     * block by {@code load_const 500000000; bin_op < (bs[i], that const);
     * assert (that compare)}. The assert runs on every path through the block
     * before any later use, so the read is a height by construction and the
     * --ir path does not count it as a locktime read (nothing derived from it
     * is a gate), as the source path does not count currentBlockHeight(). Its
     * assert still counts as a pin. Matches only that exact four-binding
     * shape. Mirrors isSelfPinnedLocktimeRead.
     */
    static boolean isSelfPinnedLocktimeRead(List<AnfBinding> bs, int i) {
        if (bs == null || i + 3 >= bs.size()) return false;
        AnfBinding r = bs.get(i);
        AnfBinding l = bs.get(i + 1);
        AnfBinding c = bs.get(i + 2);
        AnfBinding a = bs.get(i + 3);
        return r.value() instanceof Call call && "extractLocktime".equals(call.func())
            && l.value() instanceof LoadConst lc && lc.value() instanceof BigIntConst bi
            && bi.value().equals(BigInteger.valueOf(500_000_000L))
            && c.value() instanceof BinOp cmp && "<".equals(cmp.op())
            && r.name().equals(cmp.left()) && l.name().equals(cmp.right())
            && a.value() instanceof Assert as && c.name().equals(as.value());
    }

    private static boolean readsIr(List<AnfBinding> body) {
        ArrayDeque<List<AnfBinding>> work = new ArrayDeque<>();
        if (body != null) work.push(body);
        while (!work.isEmpty()) {
            List<AnfBinding> bs = work.pop();
            for (int i = 0; i < bs.size(); i++) {
                AnfBinding b = bs.get(i);
                AnfValue v = b.value();
                if (v instanceof Call c && "extractLocktime".equals(c.func()) && !isSelfPinnedLocktimeRead(bs, i)) return true;
                if (v instanceof If iff) {
                    if (iff.thenBranch() != null) work.push(iff.thenBranch());
                    if (iff.elseBranch() != null) work.push(iff.elseBranch());
                } else if (v instanceof Loop lp && lp.body() != null) {
                    work.push(lp.body());
                }
            }
        }
        return false;
    }

    /**
     * D26 on the --ir path: --ir skips typecheck, so the rule is re-derived
     * from the ANF of every public method (stateless and stateful): a bin_op
     * gate whose operand resolves (through {@code load_const "@ref:"} aliases)
     * to a {@code call extractLocktime}, and an assert whose value resolves to
     * a pin compare, or to the {@code &&} lowering (a value if whose else arm
     * is the constant false) of a chain with a pin conjunct.
     */
    static void checkIr(List<AnfMethod> methods) {
        boolean any = false;
        for (AnfMethod m : methods) if (readsIr(m.body())) any = true;
        if (!any) return;
        IrProgram prog = new IrProgram(methods);
        for (AnfMethod m : methods) {
            if (!m.isPublic() || "constructor".equals(m.name())) continue;
            if (unpinned(prog.exits(m, new int[0]))) {
                throw new RuntimeException("IR validation: " + locktimeDomainMessage(m.name()));
            }
        }
    }

    private static final class IrProgram {
        private final Map<String, AnfMethod> privates = new HashMap<>();
        private final Map<String, Integer> exitsOf = new HashMap<>();
        private final Set<String> inProgress = new HashSet<>();

        IrProgram(List<AnfMethod> methods) {
            for (AnfMethod m : methods) {
                if (!m.isPublic() && !"constructor".equals(m.name())) privates.put(m.name(), m);
            }
        }

        int exits(AnfMethod m, int[] argLevels) {
            Map<String, Integer> params = new HashMap<>();
            StringBuilder key = new StringBuilder(m.name()).append('|');
            List<AnfParam> ps = m.params() != null ? m.params() : List.of();
            for (int i = 0; i < ps.size(); i++) {
                int lv = i < argLevels.length ? argLevels[i] : NONE;
                if (lv != NONE) params.put(ps.get(i).name(), lv);
                if (i > 0) key.append(',');
                key.append(lv);
            }
            Integer cached = exitsOf.get(key.toString());
            if (cached != null) return cached;
            if (inProgress.contains(m.name())) return ZERO;
            inProgress.add(m.name());
            int ex = new IrGates(this, m, params).run(m.body(), ZERO);
            inProgress.remove(m.name());
            exitsOf.put(key.toString(), ex);
            return ex;
        }
    }

    private static final class IrGates {
        private final IrProgram prog;
        /** Every binding of the method, by name (a name bound more than once keeps all its values). */
        private final Map<String, List<AnfValue>> defs = new HashMap<>();
        private final Map<String, Integer> taint;
        /**
         * The {@code bin_op <} of each currentBlockHeight() image: its read is
         * no locktime read, but its assert still pins the domain on its path
         * (the pin bounds the transaction's nLockTime, whichever read it is
         * spelled on). By identity (ANF values are records).
         */
        private final Set<AnfValue> selfPinCompares = Collections.newSetFromMap(new IdentityHashMap<>());

        IrGates(IrProgram prog, AnfMethod method, Map<String, Integer> params) {
            this.prog = prog;
            List<String> names = new ArrayList<>();
            List<AnfValue> vals = new ArrayList<>();
            // currentBlockHeight()'s reads: not locktime reads. By identity.
            Set<AnfValue> selfPinned = Collections.newSetFromMap(new IdentityHashMap<>());
            ArrayDeque<List<AnfBinding>> work = new ArrayDeque<>();
            if (method.body() != null) work.add(method.body());
            // Breadth-first indexing: the binding order solveTaint sees does not change its result.
            while (!work.isEmpty()) {
                List<AnfBinding> block = work.poll();
                for (int i = 0; i < block.size(); i++) {
                    AnfBinding b = block.get(i);
                    if (isSelfPinnedLocktimeRead(block, i)) {
                        selfPinned.add(b.value());
                        selfPinCompares.add(block.get(i + 2).value());
                    }
                    defs.computeIfAbsent(b.name(), k -> new ArrayList<>()).add(b.value());
                    names.add(b.name());
                    vals.add(b.value());
                    if (b.value() instanceof If iff) {
                        if (iff.thenBranch() != null) work.add(iff.thenBranch());
                        if (iff.elseBranch() != null) work.add(iff.elseBranch());
                    } else if (b.value() instanceof Loop lp && lp.body() != null) {
                        work.add(lp.body());
                    }
                }
            }
            this.taint = solveTaint(
                names,
                vals,
                (v, t) -> {
                    String r = refOf(v);
                    if (r != null) return t.contains(r);
                    if (v instanceof Call c) {
                        if ("extractLocktime".equals(c.func()) && !selfPinned.contains(v)) return true;
                        for (String a : c.args()) if (t.contains(a)) return true;
                        return false;
                    }
                    if (v instanceof LoadParam lp) return params.getOrDefault(lp.name(), NONE) != NONE;
                    if (v instanceof BinOp b) return PROPAGATE.contains(b.op()) && (t.contains(b.left()) || t.contains(b.right()));
                    if (v instanceof UnaryOp u) return PROPAGATE_UNARY.contains(u.op()) && t.contains(u.operand());
                    if (v instanceof If iff) {
                        String a = lastName(iff.thenBranch());
                        String b = lastName(iff.elseBranch());
                        return (a != null && t.contains(a)) || (b != null && t.contains(b));
                    }
                    return false;
                },
                (v, d) -> {
                    String r = refOf(v);
                    if (r != null) return d.contains(r);
                    if (v instanceof Call c) return "extractLocktime".equals(c.func()) && !selfPinned.contains(v);
                    if (v instanceof LoadParam lp) return params.getOrDefault(lp.name(), NONE) == DIRECT;
                    return false;
                });
        }

        private static String lastName(List<AnfBinding> arm) {
            return arm == null || arm.isEmpty() ? null : arm.get(arm.size() - 1).name();
        }

        private int level(String name) {
            return taint.getOrDefault(name, NONE);
        }

        private AnfValue single(String name) {
            List<AnfValue> vs = defs.get(name);
            return vs != null && vs.size() == 1 ? vs.get(0) : null;
        }

        /** The bigint a name resolves to through {@code @ref:} aliases, or null. */
        private BigInteger literal(String start) {
            Set<String> seen = new HashSet<>();
            for (String name = start; name != null && seen.add(name); ) {
                AnfValue v = single(name);
                if (!(v instanceof LoadConst lc)) return null;
                if (lc.value() instanceof BigIntConst bi) return bi.value();
                name = refOf(v);
            }
            return null;
        }

        private Cls compare(AnfValue v) {
            if (!(v instanceof BinOp b)) return Cls.NONE;
            return classifyCompare(b.op(), level(b.left()), literal(b.left()), level(b.right()), literal(b.right()));
        }

        /** Does {@code assert(name)} imply a pin? Explicit work list with a seen set. */
        private boolean assertedPin(String start) {
            Set<String> seen = new HashSet<>();
            ArrayDeque<String> work = new ArrayDeque<>();
            work.push(start);
            while (!work.isEmpty()) {
                String name = work.pop();
                if (name == null || !seen.add(name)) continue;
                AnfValue v = single(name);
                if (v == null) continue;
                if (compare(v) == Cls.PIN || selfPinCompares.contains(v)) return true;
                String r = refOf(v);
                if (r != null) {
                    work.push(r);
                    continue;
                }
                // `a && b` lowers to `if a then [..., b] else [false]`.
                if (v instanceof If iff && isConstFalseArm(iff.elseBranch())
                        && iff.thenBranch() != null && !iff.thenBranch().isEmpty()) {
                    work.push(iff.cond());
                    work.push(lastName(iff.thenBranch()));
                }
            }
            return false;
        }

        int run(List<AnfBinding> bs, int states) {
            int s = states;
            if (bs == null) return s;
            for (AnfBinding b : bs) {
                AnfValue v = b.value();
                if (v instanceof BinOp) {
                    if (compare(v) == Cls.GATE) s = orAll(s, G);
                } else if (v instanceof Assert a) {
                    if (assertedPin(a.value())) s = orAll(s, P);
                } else if (v instanceof MethodCall mc) {
                    AnfMethod t = prog.privates.get(mc.method());
                    if (t != null) {
                        int[] levels = new int[mc.args().size()];
                        for (int i = 0; i < levels.length; i++) levels[i] = level(mc.args().get(i));
                        s = compose(s, prog.exits(t, levels));
                    }
                } else if (v instanceof If iff) {
                    s = run(iff.thenBranch(), s) | run(iff.elseBranch(), s);
                } else if (v instanceof Loop lp) {
                    s |= run(lp.body(), s);
                }
            }
            return s;
        }
    }

    private static boolean isConstFalseArm(List<AnfBinding> arm) {
        if (arm == null || arm.size() != 1) return false;
        return arm.get(0).value() instanceof LoadConst lc && lc.value() instanceof BoolConst bc && !bc.value();
    }
}
