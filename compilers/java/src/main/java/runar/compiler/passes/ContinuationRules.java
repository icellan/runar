package runar.compiler.passes;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AddRawOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * #199 (warning) and D18 (error): where a StatefulSmartContract's satoshis can
 * go. Port of {@code packages/runar-compiler/src/passes/continuation-rules.ts}
 * (see its header for the full rationale). Both rules read the transitive
 * continuation predicates {@link AnfLower} injects the continuation from
 * ({@code methodMutatesState}, {@code methodHasAddOutput} = addOutput OR
 * addRawOutput, {@code methodHasAddDataOutput}). AnfLower is wire-format gated
 * and its AST descent helpers are private, so D18's per-path analysis
 * ({@link SourcePaths}) lives here, with {@code exprHasAddOutput}'s callee
 * matching restricted to addOutput.
 */
public final class ContinuationRules {

    private ContinuationRules() {}

    /** #199: the shared warning text. */
    public static String releaseTrapMessage(String contract) {
        return "contract '" + contract + "' has no terminal method and no public method that calls "
            + "addOutput/addRawOutput; its satoshis can never leave instances of '" + contract + "'";
    }

    /** D18: the shared error text. */
    public static String droppedContinuationMessage(String method) {
        return "method '" + method + "' writes contract state on a path that reaches no addOutput(): a method "
            + "that declares its own outputs (addOutput/addRawOutput) gets no auto-injected continuation, "
            + "so on that path the state write would be lost and the contract's satoshis would leave with "
            + "the spend. Add this.addOutput(satoshis, ...) on every path that writes state, or stop "
            + "writing state on a path meant to end the contract";
    }

    /**
     * D18, per path: the method declares a state output somewhere (any
     * addOutput / addRawOutput, so it gets no auto-continuation) and some path
     * through it writes state without reaching an addOutput.
     */
    static boolean dropsContinuation(MethodNode m, ContractNode contract) {
        if (!AnfLower.methodHasAddOutput(m, contract)) return false;
        SourcePaths p = new SourcePaths(contract);
        p.prepare(m.body());
        return dropped(p.exits(m.body()));
    }

    // ------------------------------------------------------------------
    // Path states
    // ------------------------------------------------------------------
    //
    // A path state is two bits, W (state written) and A (addOutput reached);
    // a set of the four possible states is a 4-bit mask (bit x set iff state x
    // is live). Every call in an expression runs; if unions its arms; a loop
    // unions skipping it; a private helper call composes the caller's states
    // with the helper's exit states (fallthrough + return).

    static final int W = 1;
    static final int A = 2;
    /** The single fresh path {0}. */
    static final int ZERO = 1;

    /** Every live state x becomes x | bits. */
    static int orAll(int states, int bits) {
        int out = 0;
        for (int x = 0; x < 4; x++) if ((states >> x & 1) != 0) out |= 1 << (x | bits);
        return out;
    }

    /** {x | y : x in states, y in exits}. */
    static int compose(int states, int exits) {
        int out = 0;
        for (int y = 0; y < 4; y++) if ((exits >> y & 1) != 0) out |= orAll(states, y);
        return out;
    }

    /** Some path wrote state (W) and reached no addOutput (not A): state 1. */
    static boolean dropped(int states) {
        return (states & (1 << W)) != 0;
    }

    /** Port of continuation-rules.ts SourcePaths over this tier's AST. */
    private static final class SourcePaths {
        private record Flow(int live, int returned) {}

        private final ContractNode contract;
        private final Set<String> mutable = new HashSet<>();
        private final Map<String, Integer> exits = new HashMap<>();
        /** Non-null while collecting the helpers a body calls whose exits are unknown. */
        private List<MethodNode> missing;

        SourcePaths(ContractNode contract) {
            this.contract = contract;
            for (PropertyNode p : contract.properties()) if (!p.readonly()) mutable.add(p.name());
        }

        /** Exit states (fallthrough and return) of a body entered with a fresh path. */
        int exits(List<Statement> body) {
            Flow f = stmts(body, ZERO);
            return f.live() | f.returned();
        }

        /**
         * Compute the exits of every helper reachable from {@code body},
         * bottom-up by an explicit post-order over the call graph (N-264: no
         * host recursion across helper chains). A helper on the open path (a
         * cycle; the validator refuses recursion) stays unresolved and
         * contributes {0}.
         */
        void prepare(List<Statement> body) {
            record Frame(MethodNode helper, List<Statement> body) {}
            Set<String> open = new HashSet<>();
            ArrayDeque<Frame> stack = new ArrayDeque<>();
            stack.push(new Frame(null, body));
            while (!stack.isEmpty()) {
                Frame top = stack.peek();
                MethodNode next = null;
                for (MethodNode m : unresolved(top.body())) {
                    if (!open.contains(m.name())) {
                        next = m;
                        break;
                    }
                }
                if (next != null) {
                    open.add(next.name());
                    stack.push(new Frame(next, next.body()));
                } else {
                    stack.pop();
                    if (top.helper() != null) {
                        exits.put(top.helper().name(), exits(top.helper().body()));
                        open.remove(top.helper().name());
                    }
                }
            }
        }

        private List<MethodNode> unresolved(List<Statement> body) {
            missing = new ArrayList<>();
            try {
                exits(body);
                return missing;
            } finally {
                missing = null;
            }
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
            if (st instanceof AssignmentStatement a) {
                int s = expr(a.value(), expr(a.target(), states));
                if (writesMutable(a.target())) s = orAll(s, W);
                return new Flow(s, 0);
            }
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

        private boolean writesMutable(Expression target) {
            Expression t = target;
            while (t instanceof IndexAccessExpr ia) t = ia.object();
            return t instanceof PropertyAccessExpr pa && mutable.contains(pa.property());
        }

        /** Every call in {@code e} runs, in evaluation order. */
        private int expr(Expression e, int states) {
            if (e == null) return states;
            if (e instanceof IncrementExpr ie) {
                int s = expr(ie.operand(), states);
                return writesMutable(ie.operand()) ? orAll(s, W) : s;
            }
            if (e instanceof DecrementExpr de) {
                int s = expr(de.operand(), states);
                return writesMutable(de.operand()) ? orAll(s, W) : s;
            }
            if (e instanceof CallExpr call) {
                int s = states;
                if (call.callee() != null && !(call.callee() instanceof Identifier)) s = expr(call.callee(), s);
                for (Expression a : call.args()) s = expr(a, s);
                if (isAddOutputCallee(call.callee())) return orAll(s, A);
                MethodNode helper = AnfLower.lookupPrivateMethod(contract, calleeName(call.callee()));
                if (helper == null) return s;
                Integer ex = exits.get(helper.name());
                if (ex == null) {
                    if (missing != null) missing.add(helper);
                    ex = ZERO;
                }
                return compose(s, ex);
            }
            if (e instanceof BinaryExpr b) return expr(b.right(), expr(b.left(), states));
            if (e instanceof UnaryExpr u) return expr(u.operand(), states);
            if (e instanceof TernaryExpr t) {
                int c = expr(t.condition(), states);
                return expr(t.consequent(), c) | expr(t.alternate(), c);
            }
            if (e instanceof IndexAccessExpr ia) return expr(ia.index(), expr(ia.object(), states));
            if (e instanceof MemberExpr me) return expr(me.object(), states);
            if (e instanceof ArrayLiteralExpr al) {
                int s = states;
                for (Expression el : al.elements()) s = expr(el, s);
                return s;
            }
            return states;
        }

        /** {@code AnfLower.exprHasAddOutput}'s callee forms, addOutput only. */
        private static boolean isAddOutputCallee(Expression callee) {
            if (callee instanceof PropertyAccessExpr pa && pa.property().equals("addOutput")) return true;
            return callee instanceof MemberExpr me
                && me.object() instanceof Identifier id
                && "this".equals(id.name())
                && me.property().equals("addOutput");
        }
    }

    /** #199: the contract-level warning text, or null when it does not apply. */
    static String releaseTrapWarning(ContractNode contract) {
        if (contract.parentClass() != ParentClass.STATEFUL_SMART_CONTRACT) return null;
        int publics = 0;
        for (MethodNode m : contract.methods()) {
            if (m.visibility() != Visibility.PUBLIC) continue;
            publics++;
            boolean stateOut = AnfLower.methodHasAddOutput(m, contract);
            boolean needsChange = mutatesState(m, contract) || stateOut
                || AnfLower.methodHasAddDataOutput(m, contract);
            if (!needsChange || stateOut) return null;
        }
        return publics == 0 ? null : releaseTrapMessage(contract.name());
    }

    // ------------------------------------------------------------------
    // State writes as the rules see them
    // ------------------------------------------------------------------

    /**
     * {@link AnfLower#methodMutatesState} OR a write to an element of a mutable
     * property ({@code this.arr[i] = v}, {@code this.arr[i]++},
     * {@code this.grid[i][j] = v}). Both rules run before FixedArray expansion
     * (pass 3b), where an element write is still an index_access target that
     * AnfLower's walk (built for the expanded contract) does not count.
     */
    static boolean mutatesState(MethodNode m, ContractNode contract) {
        return AnfLower.methodMutatesState(m, contract) || writesMutableElement(m, contract);
    }

    /** Port of side-effect-summary.ts {@code writesMutableProperty}, element form only. */
    private static boolean isMutableElement(Expression target, Set<String> mutable) {
        if (!(target instanceof IndexAccessExpr)) return false;
        Expression t = target;
        while (t instanceof IndexAccessExpr ia) t = ia.object();
        return t instanceof PropertyAccessExpr pa && mutable.contains(pa.property());
    }

    /**
     * Element-write walk; same descent as AnfLower.methodMutatesState (statement
     * and expression children, private callees queued for any CallExpr, ++/--
     * not descended into).
     */
    static boolean writesMutableElement(MethodNode m, ContractNode contract) {
        Set<String> mutable = new HashSet<>();
        for (PropertyNode p : contract.properties()) {
            if (!p.readonly()) mutable.add(p.name());
        }
        if (mutable.isEmpty()) return false;
        Set<String> visited = new HashSet<>();
        ArrayDeque<List<Statement>> pending = new ArrayDeque<>();
        for (List<Statement> next = m.body(); next != null; next = pending.poll()) {
            for (Statement s : next) if (elementStmt(s, mutable, contract, visited, pending)) return true;
        }
        return false;
    }

    private static boolean elementStmt(
            Statement s, Set<String> mutable, ContractNode c, Set<String> v, ArrayDeque<List<Statement>> q) {
        if (s instanceof AssignmentStatement a && isMutableElement(a.target(), mutable)) return true;
        for (Expression e : statementExpressions(s)) if (elementExpr(e, mutable, c, v, q)) return true;
        for (Statement inner : childStatements(s)) if (elementStmt(inner, mutable, c, v, q)) return true;
        return false;
    }

    private static boolean elementExpr(
            Expression e, Set<String> mutable, ContractNode c, Set<String> v, ArrayDeque<List<Statement>> q) {
        if (e == null) return false;
        if (e instanceof IncrementExpr ie) return isMutableElement(ie.operand(), mutable);
        if (e instanceof DecrementExpr de) return isMutableElement(de.operand(), mutable);
        if (e instanceof CallExpr call) {
            MethodNode target = AnfLower.lookupPrivateMethod(c, calleeName(call.callee()));
            if (target != null && v.add(target.name())) q.add(target.body());
        }
        for (Expression child : childExpressions(e)) if (elementExpr(child, mutable, c, v, q)) return true;
        return false;
    }

    // ------------------------------------------------------------------
    // AST descent shared by the element-write walk
    // ------------------------------------------------------------------

    private static String calleeName(Expression callee) {
        if (callee instanceof PropertyAccessExpr pa) return pa.property();
        if (callee instanceof MemberExpr me) return me.property();
        if (callee instanceof Identifier id) return id.name();
        return null;
    }

    private static List<Statement> childStatements(Statement stmt) {
        List<Statement> out = new ArrayList<>();
        if (stmt instanceof IfStatement i) {
            out.addAll(i.thenBody());
            if (i.elseBody() != null) out.addAll(i.elseBody());
        } else if (stmt instanceof ForStatement f) {
            if (f.init() != null) out.add(f.init());
            if (f.update() != null) out.add(f.update());
            out.addAll(f.body());
        }
        return out;
    }

    private static List<Expression> statementExpressions(Statement stmt) {
        List<Expression> out = new ArrayList<>();
        if (stmt instanceof AssignmentStatement a) {
            if (a.target() != null) out.add(a.target());
            if (a.value() != null) out.add(a.value());
        } else if (stmt instanceof ExpressionStatement es) {
            if (es.expression() != null) out.add(es.expression());
        } else if (stmt instanceof IfStatement i) {
            if (i.condition() != null) out.add(i.condition());
        } else if (stmt instanceof ForStatement f) {
            if (f.condition() != null) out.add(f.condition());
        } else if (stmt instanceof ReturnStatement r) {
            if (r.value() != null) out.add(r.value());
        } else if (stmt instanceof VariableDeclStatement vd) {
            if (vd.init() != null) out.add(vd.init());
        }
        return out;
    }

    private static List<Expression> childExpressions(Expression expr) {
        List<Expression> out = new ArrayList<>();
        if (expr instanceof CallExpr c) {
            out.addAll(c.args());
            if (c.callee() != null && !(c.callee() instanceof Identifier)) out.add(c.callee());
        } else if (expr instanceof BinaryExpr b) {
            out.add(b.left());
            out.add(b.right());
        } else if (expr instanceof UnaryExpr u) {
            out.add(u.operand());
        } else if (expr instanceof TernaryExpr t) {
            out.add(t.condition());
            out.add(t.consequent());
            out.add(t.alternate());
        } else if (expr instanceof IndexAccessExpr ia) {
            out.add(ia.object());
            out.add(ia.index());
        } else if (expr instanceof MemberExpr me) {
            out.add(me.object());
        } else if (expr instanceof ArrayLiteralExpr al) {
            out.addAll(al.elements());
        }
        out.removeIf(java.util.Objects::isNull);
        return out;
    }

    // ------------------------------------------------------------------
    // D18 on the --ir path (port of assertIrNoDroppedContinuation)
    // ------------------------------------------------------------------

    /**
     * --ir skips typecheck, so the rule is re-derived from the ANF, per path:
     * a public method that declares an output (add_output / add_raw_output, at
     * any depth and through method_calls to private methods) and has a path
     * that reaches an update_prop but no add_output is refused with the source
     * path's text. Called for StatefulSmartContract programs after the N-101
     * scaffolding check.
     */
    static void checkIr(List<AnfMethod> methods) {
        Map<String, AnfMethod> privates = new HashMap<>();
        for (AnfMethod m : methods) {
            if (!m.isPublic() && !"constructor".equals(m.name())) privates.put(m.name(), m);
        }
        for (AnfMethod m : methods) {
            if (!m.isPublic() || "constructor".equals(m.name())) continue;
            if (irDropsContinuation(m, privates)) {
                throw new RuntimeException("IR validation: " + droppedContinuationMessage(m.name()));
            }
        }
    }

    private static boolean irDropsContinuation(AnfMethod method, Map<String, AnfMethod> privates) {
        if (!irDeclaresOutput(method, privates)) return false;
        Map<String, Integer> exits = irHelperExits(method, privates);
        return dropped(irRun(method.body(), ZERO, privates, exits));
    }

    /** Any add_output / add_raw_output at any depth, through method_calls (explicit work list). */
    private static boolean irDeclaresOutput(AnfMethod method, Map<String, AnfMethod> privates) {
        Set<String> visited = new HashSet<>();
        ArrayDeque<List<AnfBinding>> work = new ArrayDeque<>();
        work.push(method.body());
        while (!work.isEmpty()) {
            for (AnfBinding b : work.pop()) {
                Object v = b.value();
                if (v instanceof AddOutput || v instanceof AddRawOutput) return true;
                if (v instanceof MethodCall mc) {
                    AnfMethod target = privates.get(mc.method());
                    if (target != null && visited.add(target.name())) work.push(target.body());
                }
                pushArms(v, work);
            }
        }
        return false;
    }

    private static void pushArms(Object v, ArrayDeque<List<AnfBinding>> work) {
        if (v instanceof If iff) {
            if (iff.thenBranch() != null) work.push(iff.thenBranch());
            if (iff.elseBranch() != null) work.push(iff.elseBranch());
        } else if (v instanceof Loop lp && lp.body() != null) {
            work.push(lp.body());
        }
    }

    /** The private methods a binding list calls, at any depth. */
    private static List<AnfMethod> irCallees(List<AnfBinding> body, Map<String, AnfMethod> privates) {
        List<AnfMethod> out = new ArrayList<>();
        ArrayDeque<List<AnfBinding>> work = new ArrayDeque<>();
        if (body != null) work.push(body);
        while (!work.isEmpty()) {
            for (AnfBinding b : work.pop()) {
                Object v = b.value();
                if (v instanceof MethodCall mc && privates.containsKey(mc.method())) out.add(privates.get(mc.method()));
                pushArms(v, work);
            }
        }
        return out;
    }

    /**
     * Exit states of every private method reachable from {@code method},
     * bottom-up by an explicit post-order (N-264: no host recursion across
     * helper chains). A helper on the open path (a cycle) stays unresolved and
     * contributes {0}.
     */
    private static Map<String, Integer> irHelperExits(AnfMethod method, Map<String, AnfMethod> privates) {
        record Frame(AnfMethod helper, List<AnfMethod> todo) {}
        Map<String, Integer> exits = new HashMap<>();
        Set<String> open = new HashSet<>();
        ArrayDeque<Frame> stack = new ArrayDeque<>();
        stack.push(new Frame(null, irCallees(method.body(), privates)));
        while (!stack.isEmpty()) {
            Frame top = stack.peek();
            AnfMethod next = null;
            for (AnfMethod t : top.todo()) {
                if (!exits.containsKey(t.name()) && !open.contains(t.name())) {
                    next = t;
                    break;
                }
            }
            if (next != null) {
                open.add(next.name());
                stack.push(new Frame(next, irCallees(next.body(), privates)));
            } else {
                stack.pop();
                if (top.helper() != null) {
                    exits.put(top.helper().name(), irRun(top.helper().body(), ZERO, privates, exits));
                    open.remove(top.helper().name());
                }
            }
        }
        return exits;
    }

    private static int irRun(
            List<AnfBinding> bindings, int states, Map<String, AnfMethod> privates, Map<String, Integer> exits) {
        int s = states;
        if (bindings == null) return s;
        for (AnfBinding b : bindings) {
            Object v = b.value();
            if (v instanceof UpdateProp) s = orAll(s, W);
            else if (v instanceof AddOutput) s = orAll(s, A);
            else if (v instanceof MethodCall mc) {
                if (privates.containsKey(mc.method())) s = compose(s, exits.getOrDefault(mc.method(), ZERO));
            } else if (v instanceof If iff) {
                int t = iff.thenBranch() != null ? irRun(iff.thenBranch(), s, privates, exits) : s;
                int e = iff.elseBranch() != null ? irRun(iff.elseBranch(), s, privates, exits) : s;
                s = t | e;
            } else if (v instanceof Loop lp) {
                if (lp.body() != null) s |= irRun(lp.body(), s, privates, exits);
            }
        }
        return s;
    }
}
