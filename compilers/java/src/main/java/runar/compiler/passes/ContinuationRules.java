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
 * and its AST descent helpers are private, so the one new predicate (calls
 * {@code addOutput} itself) lives here with a copy of that descent and of
 * {@code exprHasAddOutput}'s callee matching, restricted to addOutput.
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
        return "method '" + method + "' writes contract state but emits no state continuation: it calls "
            + "addRawOutput() without addOutput(), and a method that declares its own outputs gets no "
            + "auto-injected continuation, so the state write would be lost and the contract's satoshis "
            + "would leave with the spend. Add this.addOutput(satoshis, ...) to carry the new state, or "
            + "stop writing state in a method meant to end the contract";
    }

    /** D18: the method writes state and only raw outputs replace its continuation. */
    static boolean dropsContinuation(MethodNode m, ContractNode contract) {
        return mutatesState(m, contract)
            && AnfLower.methodHasAddOutput(m, contract)
            && !callsAddOutput(m, contract);
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
    // addOutput-only walk (mirrors AnfLower.exprHasAddOutput)
    // ------------------------------------------------------------------

    /** Calls {@code this.addOutput(...)} itself, directly or through a private helper. */
    static boolean callsAddOutput(MethodNode m, ContractNode contract) {
        Set<String> visited = new HashSet<>();
        ArrayDeque<List<Statement>> pending = new ArrayDeque<>();
        for (List<Statement> next = m.body(); next != null; next = pending.poll()) {
            for (Statement s : next) if (stmt(s, contract, visited, pending)) return true;
        }
        return false;
    }

    private static boolean stmt(Statement s, ContractNode c, Set<String> v, ArrayDeque<List<Statement>> q) {
        for (Expression e : statementExpressions(s)) if (expr(e, c, v, q)) return true;
        for (Statement inner : childStatements(s)) if (stmt(inner, c, v, q)) return true;
        return false;
    }

    private static boolean expr(Expression e, ContractNode c, Set<String> v, ArrayDeque<List<Statement>> q) {
        if (e == null) return false;
        if (e instanceof CallExpr call) {
            if (call.callee() instanceof PropertyAccessExpr pa && pa.property().equals("addOutput")) return true;
            if (call.callee() instanceof MemberExpr me
                && me.object() instanceof Identifier id
                && "this".equals(id.name())
                && me.property().equals("addOutput")) {
                return true;
            }
            MethodNode target = AnfLower.lookupPrivateMethod(c, calleeName(call.callee()));
            if (target != null && v.add(target.name())) q.add(target.body());
        }
        for (Expression child : childExpressions(e)) if (expr(child, c, v, q)) return true;
        return false;
    }

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
     * --ir skips typecheck, so the rule is re-derived from the ANF: a public
     * method whose bindings reach an update_prop and an add_raw_output but no
     * add_output, at any depth and through method_calls to private methods, is
     * refused with the source path's text. Called for StatefulSmartContract
     * programs after the N-101 scaffolding check.
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
        boolean writes = false;
        boolean raw = false;
        boolean add = false;
        Set<String> visited = new HashSet<>();
        ArrayDeque<List<AnfBinding>> work = new ArrayDeque<>();
        work.push(method.body());
        while (!work.isEmpty()) {
            for (AnfBinding b : work.pop()) {
                Object v = b.value();
                if (v instanceof UpdateProp) writes = true;
                else if (v instanceof AddRawOutput) raw = true;
                else if (v instanceof AddOutput) add = true;
                else if (v instanceof MethodCall mc) {
                    AnfMethod target = privates.get(mc.method());
                    if (target != null && visited.add(target.name())) work.push(target.body());
                } else if (v instanceof If iff) {
                    if (iff.thenBranch() != null) work.push(iff.thenBranch());
                    if (iff.elseBranch() != null) work.push(iff.elseBranch());
                } else if (v instanceof Loop lp) {
                    if (lp.body() != null) work.push(lp.body());
                }
            }
        }
        return writes && raw && !add;
    }
}
