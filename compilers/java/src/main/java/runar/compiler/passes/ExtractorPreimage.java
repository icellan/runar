package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.CustomType;
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
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * D14 (spec/type-system.md 4.3): a preimage extractor reads only a CHECKED
 * preimage. A provenance rule on top of GK-GAP-010 ({@link PreimageChecked}):
 * the subtype rules let any ByteString stand where a SigHashPreimage is
 * expected, so typing the extractor's parameter proves nothing. Inside a
 * method a "checked preimage" is a SigHashPreimage parameter of that method
 * (a public method's is asserted on every path by GK-GAP-010; a private
 * method's is covered by the call-site rule), a local declared from one
 * (GK-010's alias rule), or, in a StatefulSmartContract, the implicit
 * txPreimage ({@code this.txPreimage} / {@code ctx.txPreimage}). A name
 * assigned anywhere in the method never counts, and nothing in a constructor
 * does. Every extractor's argument, and every argument passed to a private
 * method's SigHashPreimage parameter, must be a checked preimage.
 */
final class ExtractorPreimage {

    /** The builtins that read a field out of a sighash preimage (argument 1). */
    static final Set<String> EXTRACTORS = Set.of(
        "extractVersion", "extractHashPrevouts", "extractHashSequence", "extractOutpoint",
        "extractInputIndex", "extractScriptCode", "extractAmount", "extractSequence",
        "extractOutputHash", "extractOutputs", "extractLocktime", "extractSigHashType");

    /** The diagnostic every tier shares; {@code fn} is the extractor or private method. */
    static String message(String fn) {
        return fn + "() needs a checked SigHashPreimage: its argument must be a SigHashPreimage parameter "
            + "(one a public method must assert with checkPreimage()) or the implicit txPreimage of a "
            + "StatefulSmartContract; any other value is not bound to the spending transaction, so every "
            + "field an extractor reads from it is unverified";
    }

    private final Map<String, MethodNode> privates = new HashMap<>();
    private final boolean implicit;
    private final List<PreimageChecked.Finding> out = new ArrayList<>();
    private MethodNode method;
    private Set<String> reassigned = new HashSet<>();
    private Set<String> ctxParams = new HashSet<>();

    private ExtractorPreimage(ContractNode contract) {
        for (MethodNode m : contract.methods()) {
            if (m.visibility() != Visibility.PUBLIC) privates.put(m.name(), m);
        }
        boolean declared = false;
        for (PropertyNode p : contract.properties()) {
            if (p.name().equals("txPreimage")) declared = true;
        }
        implicit = contract.parentClass() == ParentClass.STATEFUL_SMART_CONTRACT && !declared;
    }

    static List<PreimageChecked.Finding> check(ContractNode contract) {
        ExtractorPreimage c = new ExtractorPreimage(contract);
        for (MethodNode m : contract.methods()) {
            c.method = m;
            c.reassigned = collectReassigned(m.body(), new HashSet<>());
            c.ctxParams = new HashSet<>();
            Set<String> initial = new HashSet<>();
            for (ParamNode p : m.params()) {
                if (p.type() instanceof CustomType ct && ct.name().equals("StatefulContext")) c.ctxParams.add(p.name());
                if (isPreimage(p.type())) initial.add(p.name());
            }
            c.visitStmts(m.body(), initial);
        }
        return c.out;
    }

    private static boolean isPreimage(TypeNode t) {
        return t instanceof PrimitiveType pt && pt.name() == PrimitiveTypeName.SIG_HASH_PREIMAGE;
    }

    private static Set<String> collectReassigned(List<Statement> stmts, Set<String> acc) {
        if (stmts == null) return acc;
        for (Statement s : stmts) {
            if (s instanceof AssignmentStatement a && a.target() instanceof Identifier id) acc.add(id.name());
            else if (s instanceof IfStatement i) {
                collectReassigned(i.thenBody(), acc);
                collectReassigned(i.elseBody(), acc);
            } else if (s instanceof ForStatement f) collectReassigned(f.body(), acc);
        }
        return acc;
    }

    private boolean isChecked(Expression e, Set<String> checked) {
        if (e instanceof Identifier id) return checked.contains(id.name()) && !reassigned.contains(id.name());
        // The implicit preimage only where no parameter of this method takes
        // its name (reserved-name rules refuse one; never rely on that alone).
        for (ParamNode p : method.params()) {
            if (p.name().equals("txPreimage")) return false;
        }
        if (e instanceof PropertyAccessExpr pa) return implicit && pa.property().equals("txPreimage");
        if (e instanceof MemberExpr me) {
            return implicit && me.property().equals("txPreimage")
                && me.object() instanceof Identifier oid && ctxParams.contains(oid.name());
        }
        return false;
    }

    private void report(String fn) {
        out.add(new PreimageChecked.Finding(message(fn), method.sourceLocation()));
    }

    private MethodNode privateTarget(Expression callee) {
        if (callee instanceof PropertyAccessExpr pa) return privates.get(pa.property());
        if (callee instanceof MemberExpr me) return privates.get(me.property());
        if (callee instanceof Identifier id) return privates.get(id.name());
        return null;
    }

    private void visitExpr(Expression e, Set<String> checked) {
        if (e == null) return;
        if (e instanceof CallExpr c) {
            List<Expression> args = c.args() == null ? List.of() : c.args();
            if (c.callee() instanceof Identifier id && EXTRACTORS.contains(id.name())) {
                if (args.isEmpty() || !isChecked(args.get(0), checked)) report(id.name());
            } else {
                MethodNode target = privateTarget(c.callee());
                if (target != null) {
                    List<ParamNode> ps = target.params();
                    for (int i = 0; i < ps.size(); i++) {
                        if (isPreimage(ps.get(i).type()) && (i >= args.size() || !isChecked(args.get(i), checked))) {
                            report(target.name());
                            break;
                        }
                    }
                }
            }
            visitExpr(c.callee(), checked);
            for (Expression a : args) visitExpr(a, checked);
        } else if (e instanceof BinaryExpr b) {
            visitExpr(b.left(), checked);
            visitExpr(b.right(), checked);
        } else if (e instanceof UnaryExpr u) {
            visitExpr(u.operand(), checked);
        } else if (e instanceof IncrementExpr inc) {
            visitExpr(inc.operand(), checked);
        } else if (e instanceof DecrementExpr dec) {
            visitExpr(dec.operand(), checked);
        } else if (e instanceof TernaryExpr t) {
            visitExpr(t.condition(), checked);
            visitExpr(t.consequent(), checked);
            visitExpr(t.alternate(), checked);
        } else if (e instanceof MemberExpr me) {
            visitExpr(me.object(), checked);
        } else if (e instanceof IndexAccessExpr ia) {
            visitExpr(ia.object(), checked);
            visitExpr(ia.index(), checked);
        } else if (e instanceof ArrayLiteralExpr al) {
            for (Expression el : al.elements()) visitExpr(el, checked);
        }
    }

    private void visitStmts(List<Statement> stmts, Set<String> checkedIn) {
        if (stmts == null) return;
        Set<String> checked = new HashSet<>(checkedIn);
        for (Statement s : stmts) {
            if (s instanceof VariableDeclStatement v) {
                visitExpr(v.init(), checked);
                if (v.init() != null && isChecked(v.init(), checked) && !reassigned.contains(v.name())) {
                    checked.add(v.name());
                } else {
                    checked.remove(v.name());
                }
            } else if (s instanceof AssignmentStatement a) {
                visitExpr(a.target(), checked);
                visitExpr(a.value(), checked);
            } else if (s instanceof ExpressionStatement es) {
                visitExpr(es.expression(), checked);
            } else if (s instanceof ReturnStatement r) {
                visitExpr(r.value(), checked);
            } else if (s instanceof IfStatement i) {
                visitExpr(i.condition(), checked);
                visitStmts(i.thenBody(), checked);
                visitStmts(i.elseBody(), checked);
            } else if (s instanceof ForStatement f) {
                Set<String> loop = new HashSet<>(checked);
                if (f.init() != null) {
                    visitExpr(f.init().init(), loop);
                    loop.remove(f.init().name());
                }
                visitExpr(f.condition(), loop);
                if (f.update() != null) visitStmts(List.of(f.update()), loop);
                visitStmts(f.body(), loop);
            }
        }
    }
}
