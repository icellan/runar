package runar.compiler.frontend;

import java.util.ArrayList;
import java.util.List;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.Statement;

/**
 * N-115 — normalise a reversed loop comparison to the canonical spelling.
 *
 * <p>Every later pass reads a loop's iterator off the LEFT-hand side of its
 * condition (W4, {@code validateForConditionTestsIterator}) and its bound off
 * the right. {@code 10 > i} says the same thing as {@code i < 10}, so the
 * parser rewrites it once instead of every pass learning a second spelling:
 *
 * <pre>
 *   N &gt;  i  -&gt;  i &lt;  N        N &lt;  i  -&gt;  i &gt;  N
 *   N &gt;= i  -&gt;  i &lt;= N        N &lt;= i  -&gt;  i &gt;= N
 * </pre>
 *
 * <p>The rule, identical in all seven tiers: the condition is a
 * {@code <}/{@code <=}/{@code >}/{@code >=} comparison, its RIGHT operand is
 * the loop variable, and its LEFT operand is not -&gt; swap the operands and
 * mirror the operator. Nothing else is touched, so the W4 refusals (N40, N41)
 * and the direction rule (N42) keep firing.
 */
public final class LoopCondition {
    private LoopCondition() {}

    private static Expression.BinaryOp mirrored(Expression.BinaryOp op) {
        return switch (op) {
            case LT -> Expression.BinaryOp.GT;
            case LE -> Expression.BinaryOp.GE;
            case GT -> Expression.BinaryOp.LT;
            case GE -> Expression.BinaryOp.LE;
            default -> null;
        };
    }

    private static boolean isIter(Expression e, String iter) {
        return e instanceof Identifier id && id.name().equals(iter);
    }

    /** The canonical form of {@code cond} for a loop over {@code iter} (or {@code cond}). */
    public static Expression normalize(Expression cond, String iter) {
        if (!(cond instanceof BinaryExpr bin)) return cond;
        Expression.BinaryOp m = mirrored(bin.op());
        if (m == null) return cond;
        if (!isIter(bin.right(), iter) || isIter(bin.left(), iter)) return cond;
        return new BinaryExpr(m, bin.right(), bin.left());
    }

    private static List<Statement> normalizeStatements(List<Statement> stmts) {
        if (stmts == null) return null;
        List<Statement> out = new ArrayList<>(stmts.size());
        for (Statement s : stmts) {
            if (s instanceof ForStatement f) {
                Expression cond = f.init() == null ? f.condition() : normalize(f.condition(), f.init().name());
                out.add(new ForStatement(f.init(), cond, f.update(), normalizeStatements(f.body()), f.sourceLocation()));
            } else if (s instanceof IfStatement i) {
                out.add(new IfStatement(i.condition(), normalizeStatements(i.thenBody()),
                    normalizeStatements(i.elseBody()), i.sourceLocation()));
            } else {
                out.add(s);
            }
        }
        return out;
    }

    private static MethodNode normalizeMethod(MethodNode m) {
        if (m == null) return null;
        return new MethodNode(m.name(), m.params(), normalizeStatements(m.body()), m.visibility(),
            m.sourceLocation(), m.sighashType(), m.bindingVariant());
    }

    /** {@code contract} with every loop condition rewritten to its canonical spelling. */
    public static ContractNode normalizeContract(ContractNode c) {
        if (c == null) return null;
        List<MethodNode> methods = new ArrayList<>(c.methods().size());
        for (MethodNode m : c.methods()) methods.add(normalizeMethod(m));
        return new ContractNode(c.name(), c.parentClass(), c.properties(), normalizeMethod(c.constructor()),
            methods, c.sourceFile());
    }
}
