package runar.compiler.frontend;

import java.util.ArrayList;
import java.util.List;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;

/**
 * N-511: on the surfaces whose trailing expression IS the value (.runar.rs and
 * .runar.move with a declared return type, .runar.rb private helpers) the
 * trailing expression statement becomes an explicit return, recursively
 * through the arms of a trailing if/else ({@code if c { x } else { 0 }}) when
 * {@code intoArms}. The return keeps the expression statement's own source
 * location, so the lowered ANF is unchanged; the type checker then needs no
 * tail-value heuristic.
 */
final class TailReturn {
    private TailReturn() {}

    static List<Statement> promote(List<Statement> stmts, boolean intoArms) {
        if (stmts == null || stmts.isEmpty()) return stmts;
        int last = stmts.size() - 1;
        Statement s = stmts.get(last);
        Statement replaced = null;
        if (s instanceof ExpressionStatement es) {
            replaced = new ReturnStatement(es.expression(), es.sourceLocation());
        } else if (intoArms && s instanceof IfStatement f && f.elseBody() != null) {
            replaced = new IfStatement(f.condition(), promote(f.thenBody(), true),
                promote(f.elseBody(), true), f.sourceLocation());
        }
        if (replaced == null) return stmts;
        List<Statement> out = new ArrayList<>(stmts);
        out.set(last, replaced);
        return out;
    }

    /** Whether a {@code return <value>} appears anywhere in the list. */
    static boolean hasValueReturn(List<Statement> stmts) {
        if (stmts == null) return false;
        for (Statement s : stmts) {
            if (s instanceof ReturnStatement r) {
                if (r.value() != null) return true;
            } else if (s instanceof IfStatement f) {
                if (hasValueReturn(f.thenBody()) || hasValueReturn(f.elseBody())) return true;
            } else if (s instanceof ForStatement f) {
                if (hasValueReturn(f.body())) return true;
            }
        }
        return false;
    }
}
