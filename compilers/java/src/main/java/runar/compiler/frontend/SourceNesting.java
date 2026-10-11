package runar.compiler.frontend;

import java.util.ArrayDeque;
import java.util.List;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.FixedArrayType;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParamNode;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;

/**
 * F-213: the source nesting limit, {@link InputLimits#MAX_SOURCE_NESTING}.
 *
 * <p>MAX_SOURCE_BYTES never bounded recursion: 2,000 nested parens is a 4 KB
 * file, and every hand-written parser here answered it with a
 * StackOverflowError. Two measures, defined in
 * {@code packages/runar-ir-schema/src/input-limits.ts} and computed the same
 * way by every tier (TS reference: {@code passes/source-limits.ts}):
 * <ul>
 *   <li>(A) parse nesting — a {@link Counter} each parser bumps around every
 *       statement, full-expression entry, prefix-unary operand and nested
 *       type argument;</li>
 *   <li>(B) AST nesting — {@link #astTooDeep} on the finished tree, which
 *       bounds every later pass and catches the left-deep trees the parsers
 *       build in loops ({@code a + a + ...}).</li>
 * </ul>
 * Either one past the limit is refused with {@link #MESSAGE}.
 */
public final class SourceNesting {
    private SourceNesting() {}

    private static final int MAX = InputLimits.MAX_SOURCE_NESTING;

    /** The one diagnostic every tier emits for an over-nested source. */
    public static final String MESSAGE =
        "source nesting depth exceeds MAX_SOURCE_NESTING (limit=" + MAX + ")";

    /**
     * Thrown by {@link Counter} to unwind a parser at the limit. Each
     * per-format {@code parse} entry turns it into that parser's own
     * ParseException carrying {@link #MESSAGE}.
     */
    public static final class LimitExceeded extends RuntimeException {
        public LimitExceeded() {
            super(MESSAGE, null, false, false);
        }
    }

    /** A body run one nesting level deeper; may throw a checked exception. */
    @FunctionalInterface
    public interface Body<T, E extends Exception> {
        T get() throws E;
    }

    /** Measure (A): the parse-nesting counter. */
    public static final class Counter {
        private int depth;

        public void enter() {
            if (++depth > MAX) throw new LimitExceeded();
        }

        public void exit() {
            depth--;
        }

        /** Run {@code body} one level deeper. */
        public <T, E extends Exception> T nested(Body<T, E> body) throws E {
            enter();
            try {
                return body.get();
            } finally {
                exit();
            }
        }
    }

    /**
     * Run a parser entry, mapping both nesting refusals to {@link #MESSAGE}:
     * {@link LimitExceeded} from measure (A), and a StackOverflowError — with
     * (A) bounding every parser's own recursion, the stack can only run out in
     * a recursive pass over a tree thousands of levels deep (built by a loop),
     * far past the limit, before measure (B) ran. Mirrors TS
     * {@code withNestingLimit}'s RangeError mapping. On success measure (B)
     * is checked on the returned contract. {@code wrap} builds the caller's
     * own exception type from the message.
     */
    public static <E extends Exception> ContractNode guard(
        Body<ContractNode, E> run,
        java.util.function.Function<String, E> wrap
    ) throws E {
        ContractNode c;
        try {
            c = run.get();
        } catch (LimitExceeded | StackOverflowError e) {
            throw wrap.apply(MESSAGE);
        }
        if (c != null && astTooDeep(c)) throw wrap.apply(MESSAGE);
        return c;
    }

    // ---------------------------------------------------------------
    // Measure (B)
    // ---------------------------------------------------------------

    /**
     * True iff some node of the contract is nested past the limit: for every
     * statement at level k (a body's top level is 1; if/else/for bodies and a
     * for's init/update are one deeper), every expression slot has
     * {@code k + exprDepth > MAX}; a property initializer sits at level 0;
     * every property / parameter / variable type has {@code typeDepth > MAX}.
     * Iterative, so it is safe on an arbitrarily deep tree.
     */
    public static boolean astTooDeep(ContractNode contract) {
        for (PropertyNode p : contract.properties()) {
            if (typeTooDeep(p.type())) return true;
            if (p.initializer() != null && exprTooDeep(p.initializer(), 1)) return true;
        }
        ArrayDeque<MethodNode> methods = new ArrayDeque<>();
        if (contract.constructor() != null) methods.add(contract.constructor());
        methods.addAll(contract.methods());
        for (MethodNode m : methods) {
            if (m.params() != null) {
                for (ParamNode p : m.params()) if (typeTooDeep(p.type())) return true;
            }
            if (m.body() != null && stmtsTooDeep(m.body(), 1)) return true;
        }
        return false;
    }

    private static boolean typeTooDeep(TypeNode t) {
        int depth = 0;
        for (TypeNode cur = t; cur != null;
             cur = cur instanceof FixedArrayType fa ? fa.element() : null) {
            if (++depth > MAX) return true;
        }
        return false;
    }

    private record Level(List<Statement> stmts, int level) {}

    private static boolean stmtsTooDeep(List<Statement> body, int topLevel) {
        ArrayDeque<Level> work = new ArrayDeque<>();
        work.push(new Level(body, topLevel));
        while (!work.isEmpty()) {
            Level l = work.pop();
            int level = l.level();
            for (Statement st : l.stmts()) {
                if (st == null) continue;
                if (level > MAX) return true;
                if (st instanceof VariableDeclStatement v) {
                    if (typeTooDeep(v.type())) return true;
                    if (exprTooDeep(v.init(), level + 1)) return true;
                } else if (st instanceof AssignmentStatement a) {
                    if (exprTooDeep(a.target(), level + 1) || exprTooDeep(a.value(), level + 1)) return true;
                } else if (st instanceof ExpressionStatement es) {
                    if (exprTooDeep(es.expression(), level + 1)) return true;
                } else if (st instanceof ReturnStatement r) {
                    if (exprTooDeep(r.value(), level + 1)) return true;
                } else if (st instanceof IfStatement i) {
                    if (exprTooDeep(i.condition(), level + 1)) return true;
                    if (i.thenBody() != null) work.push(new Level(i.thenBody(), level + 1));
                    if (i.elseBody() != null) work.push(new Level(i.elseBody(), level + 1));
                } else if (st instanceof ForStatement f) {
                    if (exprTooDeep(f.condition(), level + 1)) return true;
                    java.util.ArrayList<Statement> initUpdate = new java.util.ArrayList<>(2);
                    if (f.init() != null) initUpdate.add(f.init());
                    if (f.update() != null) initUpdate.add(f.update());
                    work.push(new Level(initUpdate, level + 1));
                    if (f.body() != null) work.push(new Level(f.body(), level + 1));
                }
            }
        }
        return false;
    }

    private record Node(Expression e, int level) {}

    /** True iff a node of {@code root} (itself at {@code level}) is past the limit. Iterative. */
    private static boolean exprTooDeep(Expression root, int level) {
        if (root == null) return false;
        ArrayDeque<Node> work = new ArrayDeque<>();
        work.push(new Node(root, level));
        while (!work.isEmpty()) {
            Node n = work.pop();
            if (n.e() == null) continue;
            if (n.level() > MAX) return true;
            int next = n.level() + 1;
            Expression e = n.e();
            if (e instanceof BinaryExpr b) {
                work.push(new Node(b.left(), next));
                work.push(new Node(b.right(), next));
            } else if (e instanceof UnaryExpr u) {
                work.push(new Node(u.operand(), next));
            } else if (e instanceof CallExpr c) {
                work.push(new Node(c.callee(), next));
                if (c.args() != null) for (Expression a : c.args()) work.push(new Node(a, next));
            } else if (e instanceof MemberExpr m) {
                work.push(new Node(m.object(), next));
            } else if (e instanceof TernaryExpr t) {
                work.push(new Node(t.condition(), next));
                work.push(new Node(t.consequent(), next));
                work.push(new Node(t.alternate(), next));
            } else if (e instanceof IndexAccessExpr ia) {
                work.push(new Node(ia.object(), next));
                work.push(new Node(ia.index(), next));
            } else if (e instanceof IncrementExpr ie) {
                work.push(new Node(ie.operand(), next));
            } else if (e instanceof DecrementExpr de) {
                work.push(new Node(de.operand(), next));
            } else if (e instanceof ArrayLiteralExpr al) {
                if (al.elements() != null) for (Expression x : al.elements()) work.push(new Node(x, next));
            }
        }
        return false;
    }
}
