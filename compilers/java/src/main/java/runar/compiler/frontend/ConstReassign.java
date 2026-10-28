package runar.compiler.frontend;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.SourceLocation;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.VariableDeclStatement;

/**
 * N-342 — a {@code const} local on the {@code .runar.ts} surface cannot be
 * reassigned; since N-344 the same holds for {@code .runar.rs} ({@code let}
 * without {@code mut}) and {@code .runar.zig} ({@code const}).
 *
 * <p>spec/grammar.md section 9: "{@code const} variables cannot be
 * reassigned." The Java AST's {@link VariableDeclStatement} carries no
 * mutability, so {@link TsParser}, {@link RustParser} and {@link ZigParser} hand
 * this pass the set of declarations (by identity) they read as immutable. Refused, with one sentence in all seven
 * tiers: {@code x = e} (and the compound forms the parser desugars to it),
 * {@code x++} / {@code ++x} / {@code x--} / {@code --x}, and a {@code const}
 * for-initializer, which the loop's own {@code i++} then advances. Element
 * writes ({@code x[0] = e}) are not touched. Scoping follows blocks. Runs on
 * the {@code .runar.ts}, {@code .runar.rs} and {@code .runar.zig} parse results.
 */
final class ConstReassign {
    /** The one sentence every tier emits for reassigning const {@code name}. */
    static String message(String name) {
        return "Cannot assign to '" + name + "' because it is a constant.";
    }

    private final List<Map<String, Boolean>> scopes = new ArrayList<>();
    private final Set<VariableDeclStatement> constDecls;
    private final String fileName;
    private final List<String> out;

    private ConstReassign(Set<VariableDeclStatement> constDecls, String fileName, List<String> out) {
        this.constDecls = constDecls;
        this.fileName = fileName;
        this.out = out;
    }

    /** A diagnostic for every reassigned {@code const} local in {@code contract}. */
    static List<String> check(ContractNode contract, Set<VariableDeclStatement> constDecls, String fileName) {
        List<String> out = new ArrayList<>();
        if (contract == null) return out;
        ConstReassign c = new ConstReassign(constDecls, fileName, out);
        if (contract.constructor() != null) c.walk(contract.constructor().body());
        for (MethodNode m : contract.methods()) c.walk(m.body());
        return out;
    }

    private Boolean lookup(String name) {
        for (int i = scopes.size() - 1; i >= 0; i--) {
            Boolean m = scopes.get(i).get(name);
            if (m != null) return m;
        }
        return null;
    }

    private void checkTarget(Expression target, SourceLocation loc) {
        if (target instanceof Identifier id && Boolean.FALSE.equals(lookup(id.name()))) {
            out.add(LexDiag.at(fileName, loc.line(), loc.column(), message(id.name())));
        }
    }

    private void checkSimple(Statement stmt) {
        if (stmt instanceof AssignmentStatement a) {
            checkTarget(a.target(), a.sourceLocation());
        } else if (stmt instanceof ExpressionStatement e) {
            if (e.expression() instanceof IncrementExpr inc) {
                checkTarget(inc.operand(), e.sourceLocation());
            } else if (e.expression() instanceof DecrementExpr dec) {
                checkTarget(dec.operand(), e.sourceLocation());
            }
        }
    }

    private void walk(List<Statement> stmts) {
        Map<String, Boolean> here = new HashMap<>();
        scopes.add(here);
        for (Statement stmt : stmts == null ? List.<Statement>of() : stmts) {
            if (stmt instanceof VariableDeclStatement d) {
                here.put(d.name(), !constDecls.contains(d));
            } else if (stmt instanceof IfStatement s) {
                walk(s.thenBody());
                walk(s.elseBody());
            } else if (stmt instanceof ForStatement f) {
                Map<String, Boolean> loop = new HashMap<>();
                if (f.init() != null) loop.put(f.init().name(), !constDecls.contains(f.init()));
                scopes.add(loop);
                if (f.update() != null) checkSimple(f.update());
                walk(f.body());
                scopes.remove(scopes.size() - 1);
            } else {
                checkSimple(stmt);
            }
        }
        scopes.remove(scopes.size() - 1);
    }
}
