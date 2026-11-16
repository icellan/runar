package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParamNode;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.SourceLocation;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * GK-GAP-010: a public method's SigHashPreimage parameter must reach
 * {@code checkPreimage} on every path.
 *
 * <p>spec/type-system.md 4.2: a SigHashPreimage parameter of a public method
 * is checked exactly once. The affine checker refuses a second consumption;
 * this refuses none. Every field an extractor reads from an unchecked
 * preimage is chosen by the spender.
 *
 * <p>A must-analysis over the AST. A parameter counts as checked by a
 * statement list when {@code checkPreimage(p)} is the asserted condition of
 * {@code assert(...)} (the whole condition or any conjunct of its top-level
 * {@code &&} chain) with {@code p} the parameter or a local alias of it, or
 * when it is passed to a private method that itself checks that parameter on
 * every path, at a point every execution of the list reaches
 * (R2-GK010-ASSERT: a discarded, bound, negated, {@code ||}-ed, compared or
 * ternary-wrapped call, or one used as an {@code if} / ternary condition or
 * returned from a helper, checks nothing):
 * an {@code if} checks it only if both arms do (a missing else checks
 * nothing), a ternary only if both arms do; the right operand of
 * {@code &&} / {@code ||} and a {@code for} loop body check nothing. A
 * {@code return} ends its path: a private method checks a parameter only if
 * every {@code return} (and the fall-through end) is reached after the
 * check, and an arm that returns drops out of the join after its {@code if}.
 * A name assigned anywhere in the method body (the parameter itself or a
 * local) never stands for a parameter.
 */
final class PreimageChecked {

    record Finding(String message, SourceLocation loc) {}

    /** The diagnostic every tier shares. */
    static String message(String method, String param) {
        return "public method '" + method + "' must pass its SigHashPreimage parameter '" + param
            + "' to checkPreimage() on every path";
    }

    private final Map<String, MethodNode> privates = new HashMap<>();
    private final Map<String, Set<Integer>> memo = new HashMap<>();
    private Set<String> reassigned = new HashSet<>();

    private static Set<String> collectReassigned(List<Statement> stmts, Set<String> out) {
        if (stmts == null) return out;
        for (Statement s : stmts) {
            if (s instanceof AssignmentStatement a && a.target() instanceof Identifier id) out.add(id.name());
            else if (s instanceof IfStatement i) {
                collectReassigned(i.thenBody(), out);
                collectReassigned(i.elseBody(), out);
            } else if (s instanceof runar.compiler.ir.ast.ForStatement f) collectReassigned(f.body(), out);
        }
        return out;
    }

    private PreimageChecked(ContractNode contract) {
        for (MethodNode m : contract.methods()) {
            if (m.visibility() != Visibility.PUBLIC) privates.put(m.name(), m);
        }
    }

    static List<Finding> check(ContractNode contract) {
        PreimageChecked pc = new PreimageChecked(contract);
        List<Finding> out = new ArrayList<>();
        for (MethodNode m : contract.methods()) {
            if (m.visibility() != Visibility.PUBLIC) continue;
            Map<String, String> aliases = new HashMap<>();
            List<String> tracked = new ArrayList<>();
            for (ParamNode p : m.params()) {
                if (isPreimage(p.type())) {
                    aliases.put(p.name(), p.name());
                    tracked.add(p.name());
                }
            }
            if (tracked.isEmpty()) continue;
            pc.reassigned = collectReassigned(m.body(), new HashSet<>());
            Set<String> done = pc.walkMethod(m.body(), aliases, Set.of(m.name()));
            for (String name : tracked) {
                if (!done.contains(name)) out.add(new Finding(message(m.name(), name), m.sourceLocation()));
            }
        }
        return out;
    }

    private static boolean isPreimage(TypeNode t) {
        return t instanceof PrimitiveType pt && pt.name() == PrimitiveTypeName.SIG_HASH_PREIMAGE;
    }

    private String resolve(Expression e, Map<String, String> aliases) {
        return e instanceof Identifier id && !reassigned.contains(id.name()) ? aliases.get(id.name()) : null;
    }

    private MethodNode privateTarget(Expression callee) {
        if (callee instanceof PropertyAccessExpr pa) return privates.get(pa.property());
        if (callee instanceof MemberExpr me) return privates.get(me.property());
        if (callee instanceof Identifier id) return privates.get(id.name());
        return null;
    }

    private Set<Integer> mustParams(MethodNode m, Set<String> stack) {
        Set<Integer> cached = memo.get(m.name());
        if (cached != null) return cached;
        if (stack.contains(m.name())) return Set.of();
        Map<String, String> aliases = new HashMap<>();
        for (ParamNode p : m.params()) {
            if (isPreimage(p.type())) aliases.put(p.name(), p.name());
        }
        Set<String> inner = new HashSet<>(stack);
        inner.add(m.name());
        Set<String> outer = reassigned;
        reassigned = collectReassigned(m.body(), new HashSet<>());
        Set<String> done = walkMethod(m.body(), new HashMap<>(aliases), inner);
        reassigned = outer;
        Set<Integer> result = new HashSet<>();
        for (int i = 0; i < m.params().size(); i++) {
            String n = m.params().get(i).name();
            if (aliases.containsKey(n) && done.contains(n)) result.add(i);
        }
        memo.put(m.name(), result);
        return result;
    }

    /** The operands of a top-level {@code &&} chain ({@code e} itself if it is not one). */
    private static void conjuncts(Expression e, List<Expression> out) {
        if (e instanceof BinaryExpr b && b.op() == Expression.BinaryOp.AND) {
            conjuncts(b.left(), out);
            conjuncts(b.right(), out);
        } else {
            out.add(e);
        }
    }

    private Set<String> exprMust(Expression e, Map<String, String> aliases, Set<String> stack) {
        Set<String> out = new LinkedHashSet<>();
        if (e == null) return out;
        if (e instanceof CallExpr c) {
            for (Expression a : c.args()) out.addAll(exprMust(a, aliases, stack));
            if (c.callee() instanceof MemberExpr me) out.addAll(exprMust(me.object(), aliases, stack));
            // R2-GK010-ASSERT: the call alone checks nothing; only an asserted
            // conjunct does (the assert branch below).
            if (c.callee() instanceof Identifier id && "checkPreimage".equals(id.name())) {
                return out;
            }
            // The Java tier keeps the Java surface's assertThat(...) as its own
            // callee name (Typecheck / Validate / AnfLower treat it as assert).
            if (c.callee() instanceof Identifier id && ("assert".equals(id.name()) || "assertThat".equals(id.name()))) {
                List<Expression> cs = new ArrayList<>();
                if (!c.args().isEmpty()) conjuncts(c.args().get(0), cs);
                for (Expression x : cs) {
                    if (x instanceof CallExpr cc && cc.callee() instanceof Identifier cid
                            && "checkPreimage".equals(cid.name()) && !cc.args().isEmpty()) {
                        String o = resolve(cc.args().get(0), aliases);
                        if (o != null) out.add(o);
                    }
                }
                return out;
            }
            MethodNode target = privateTarget(c.callee());
            if (target != null) {
                for (int i : mustParams(target, stack)) {
                    if (i < c.args().size()) {
                        String o = resolve(c.args().get(i), aliases);
                        if (o != null) out.add(o);
                    }
                }
            }
        } else if (e instanceof BinaryExpr b) {
            out.addAll(exprMust(b.left(), aliases, stack));
            if (b.op() != Expression.BinaryOp.AND && b.op() != Expression.BinaryOp.OR) {
                out.addAll(exprMust(b.right(), aliases, stack));
            }
        } else if (e instanceof TernaryExpr t) {
            out.addAll(exprMust(t.condition(), aliases, stack));
            Set<String> arms = exprMust(t.consequent(), aliases, stack);
            arms.retainAll(exprMust(t.alternate(), aliases, stack));
            out.addAll(arms);
        } else if (e instanceof UnaryExpr u) {
            out.addAll(exprMust(u.operand(), aliases, stack));
        } else if (e instanceof IndexAccessExpr ia) {
            out.addAll(exprMust(ia.object(), aliases, stack));
            out.addAll(exprMust(ia.index(), aliases, stack));
        } else if (e instanceof MemberExpr me) {
            out.addAll(exprMust(me.object(), aliases, stack));
        } else if (e instanceof ArrayLiteralExpr al) {
            for (Expression el : al.elements()) out.addAll(exprMust(el, aliases, stack));
        }
        return out;
    }

    /** Intersects the checked sets of every return and of the fall-through end of a method body. */
    private Set<String> walkMethod(List<Statement> body, Map<String, String> aliases, Set<String> stack) {
        List<Set<String>> exits = new ArrayList<>();
        Set<String> fall = walk(body, new HashSet<>(), aliases, stack, exits);
        if (fall != null) exits.add(fall);
        Set<String> done = exits.isEmpty() ? new HashSet<>() : new HashSet<>(exits.get(0));
        for (Set<String> e : exits) done.retainAll(e);
        return done;
    }

    /**
     * The parameters checked at the end of {@code stmts}, or {@code null} when
     * every path through {@code stmts} returns first. Each return records its
     * own checked set in {@code exits}.
     */
    private Set<String> walk(
            List<Statement> stmts, Set<String> doneIn, Map<String, String> aliases, Set<String> stack,
            List<Set<String>> exits) {
        Set<String> done = new HashSet<>(doneIn);
        if (stmts == null) return done;
        for (Statement s : stmts) {
            if (s instanceof VariableDeclStatement v) {
                done.addAll(exprMust(v.init(), aliases, stack));
                String o = v.init() == null ? null : resolve(v.init(), aliases);
                if (o != null) aliases.put(v.name(), o);
                else aliases.remove(v.name());
            } else if (s instanceof AssignmentStatement a) {
                done.addAll(exprMust(a.value(), aliases, stack));
            } else if (s instanceof ExpressionStatement es) {
                done.addAll(exprMust(es.expression(), aliases, stack));
            } else if (s instanceof ReturnStatement r) {
                done.addAll(exprMust(r.value(), aliases, stack));
                exits.add(done);
                return null;
            } else if (s instanceof IfStatement i) {
                done.addAll(exprMust(i.condition(), aliases, stack));
                Set<String> thenDone = walk(i.thenBody(), done, new HashMap<>(aliases), stack, exits);
                Set<String> elseDone = walk(i.elseBody(), done, new HashMap<>(aliases), stack, exits);
                if (thenDone == null && elseDone == null) return null;
                if (thenDone == null) {
                    done = elseDone;
                } else if (elseDone == null) {
                    done = thenDone;
                } else {
                    thenDone.retainAll(elseDone);
                    done = thenDone;
                }
            } else if (s instanceof runar.compiler.ir.ast.ForStatement f) {
                // The body checks nothing for the code after the loop, but a
                // return inside it still ends a path.
                walk(f.body(), done, new HashMap<>(aliases), stack, exits);
            }
        }
        return done;
    }
}
