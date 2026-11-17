package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;

/**
 * D15: the preimage rules on {@code --ir} input. Port of
 * packages/runar-compiler/src/passes/ir-preimage-rules.ts (see its header for
 * the full rule and for what ANF cannot carry). {@code --ir} skips the
 * frontend, so D9 (no SigHashPreimage property), GK-GAP-010 (a public
 * method's SigHashPreimage parameter is asserted on every path) and D14 (an
 * extractor reads only a checked preimage) are re-derived here, failing
 * closed.
 */
public final class IrPreimageRules {

    private static final String SHP = "SigHashPreimage";

    private IrPreimageRules() {}

    static String preimagePropertyMessage(String name) {
        return "property '" + name + "' cannot hold a SigHashPreimage: a preimage stored in a property was "
            + "fixed before the spending transaction existed, so it can never pass checkPreimage() and every "
            + "field an extractor reads from it is unverified";
    }

    /** {@code null} stands for "everything" (what a constant-false arm implies). */
    private static Set<String> union(Set<String> a, Set<String> b) {
        if (a == null || b == null) return null;
        Set<String> out = new HashSet<>(a);
        out.addAll(b);
        return out;
    }

    private static Set<String> intersect(Set<String> a, Set<String> b) {
        if (a == null) return b;
        if (b == null) return a;
        Set<String> out = new HashSet<>(a);
        out.retainAll(b);
        return out;
    }

    private static String refTarget(AnfValue v) {
        if (v instanceof LoadConst lc && lc.value() instanceof BytesConst bc
            && bc.hex() != null && bc.hex().startsWith("@ref:")) {
            return bc.hex().substring(5);
        }
        return null;
    }

    private static List<AnfBinding> orEmpty(List<AnfBinding> l) {
        return l == null ? List.of() : l;
    }

    private static final class View {
        final Map<String, AnfValue> defs = new HashMap<>();
        final Set<String> dup = new HashSet<>();
        final Set<String> shp = new HashSet<>();
        final boolean implicit;

        View(AnfMethod m, boolean implicitTx) {
            collect(m.body());
            boolean own = false;
            for (AnfParam p : m.params()) {
                if (SHP.equals(p.type())) shp.add(p.name());
                if ("txPreimage".equals(p.name())) own = true;
            }
            implicit = !m.isPublic() && implicitTx && !own;
        }

        void collect(List<AnfBinding> bs) {
            for (AnfBinding b : orEmpty(bs)) {
                if (defs.containsKey(b.name())) dup.add(b.name());
                defs.put(b.name(), b.value());
                if (b.value() instanceof If iff) {
                    collect(iff.thenBranch());
                    collect(iff.elseBranch());
                } else if (b.value() instanceof Loop loop) {
                    collect(loop.body());
                }
            }
        }

        String resolve(String name) {
            Set<String> seen = new HashSet<>();
            while (name != null && !dup.contains(name) && seen.add(name)) {
                AnfValue v = defs.get(name);
                if (v == null) return null;
                if (v instanceof LoadParam lp) {
                    if (shp.contains(lp.name())) return lp.name();
                    return implicit && "txPreimage".equals(lp.name()) ? lp.name() : null;
                }
                if (v instanceof LoadProp lp) return implicit && "txPreimage".equals(lp.name()) ? lp.name() : null;
                name = refTarget(v);
            }
            return null;
        }

        Set<String> truthChecks(String name, Set<String> seen) {
            if (name == null || dup.contains(name) || !seen.add(name)) return new HashSet<>();
            AnfValue v = defs.get(name);
            if (v == null) return new HashSet<>();
            if (v instanceof CheckPreimage cp) {
                String o = resolve(cp.preimage());
                return o == null ? new HashSet<>() : new HashSet<>(Set.of(o));
            }
            if (v instanceof LoadConst lc) {
                if (lc.value() instanceof BoolConst bc && !bc.value()) return null;
                String next = refTarget(v);
                return next == null ? new HashSet<>() : truthChecks(next, seen);
            }
            if (v instanceof If iff) {
                List<AnfBinding> t = orEmpty(iff.thenBranch());
                List<AnfBinding> e = orEmpty(iff.elseBranch());
                if ((iff.results() != null && !iff.results().isEmpty()) || t.isEmpty() || e.isEmpty()) {
                    return new HashSet<>();
                }
                Set<String> both = union(truthChecks(iff.cond(), seen), truthChecks(t.get(t.size() - 1).name(), seen));
                return intersect(both, truthChecks(e.get(e.size() - 1).name(), seen));
            }
            return new HashSet<>();
        }
    }

    /** A method_call target, resolved as {@link StackLower#privateMethodMap} does. */
    private Map<String, AnfMethod> privates = new HashMap<>();
    /** Keyed by method identity, never by name. */
    private final Map<AnfMethod, Set<String>> memo = new java.util.IdentityHashMap<>();
    private boolean implicitTx;

    private Set<String> mustChecked(AnfMethod m, Set<AnfMethod> stack) {
        Set<String> cached = memo.get(m);
        if (cached != null) return cached;
        if (stack.contains(m)) return new HashSet<>();
        View mv = new View(m, implicitTx);
        Set<AnfMethod> inner = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        inner.addAll(stack);
        inner.add(m);
        Set<String> result = walk(mv, m.body(), new HashSet<>(), inner);
        memo.put(m, result);
        return result;
    }

    private Set<String> walk(View mv, List<AnfBinding> bs, Set<String> doneIn, Set<AnfMethod> inner) {
        Set<String> done = new HashSet<>(doneIn);
        for (AnfBinding b : orEmpty(bs)) {
            AnfValue v = b.value();
            if (v instanceof Assert a) {
                Set<String> c = mv.truthChecks(a.value(), new HashSet<>());
                if (c != null) done.addAll(c);
            } else if (v instanceof If iff) {
                Set<String> t = walk(mv, iff.thenBranch(), done, inner);
                Set<String> e = walk(mv, iff.elseBranch(), done, inner);
                t.retainAll(e);
                done = t;
            } else if (v instanceof MethodCall mc) {
                AnfMethod target = privates.get(mc.method());
                if (target != null) {
                    Set<String> checked = mustChecked(target, inner);
                    List<String> args = mc.args() == null ? List.of() : mc.args();
                    for (int i = 0; i < target.params().size() && i < args.size(); i++) {
                        if (!checked.contains(target.params().get(i).name())) continue;
                        String o = mv.resolve(args.get(i));
                        if (o != null) done.add(o);
                    }
                }
            }
        }
        return done;
    }

    private void visit(View mv, List<AnfBinding> bs, List<String> errors) {
        for (AnfBinding b : orEmpty(bs)) {
            AnfValue v = b.value();
            if (v instanceof Call c && ExtractorPreimage.EXTRACTORS.contains(c.func())) {
                List<String> args = c.args() == null ? List.of() : c.args();
                if (mv.resolve(args.isEmpty() ? null : args.get(0)) == null) {
                    errors.add(ExtractorPreimage.message(c.func()));
                }
            } else if (v instanceof MethodCall mc) {
                AnfMethod target = privates.get(mc.method());
                if (target != null) {
                    List<String> args = mc.args() == null ? List.of() : mc.args();
                    for (int i = 0; i < target.params().size(); i++) {
                        if (!SHP.equals(target.params().get(i).type())) continue;
                        if (i >= args.size() || mv.resolve(args.get(i)) == null) {
                            errors.add(ExtractorPreimage.message(target.name()));
                            break;
                        }
                    }
                }
            } else if (v instanceof If iff) {
                visit(mv, iff.thenBranch(), errors);
                visit(mv, iff.elseBranch(), errors);
            } else if (v instanceof Loop loop) {
                visit(mv, loop.body(), errors);
            }
        }
    }

    /** Every D9 / GK-GAP-010 / D14 violation on the ANF, in a stable order. */
    static List<String> errors(List<AnfProperty> props, List<AnfMethod> methodList) {
        List<String> errors = new ArrayList<>();
        for (AnfProperty p : props) {
            if (SHP.equals(p.type())) errors.add(preimagePropertyMessage(p.name()));
        }
        IrPreimageRules r = new IrPreimageRules();
        int publics = 0;
        boolean allHaveTx = true;
        // As stack lowering inlines a method_call: the LAST non-public,
        // non-constructor method of that name. The loader refuses duplicate
        // names first; this never relies on that alone.
        for (AnfMethod m : methodList) {
            if (!m.isPublic() && !"constructor".equals(m.name())) r.privates.put(m.name(), m);
        }
        for (AnfMethod m : methodList) {
            if (!m.isPublic() || "constructor".equals(m.name())) continue;
            publics++;
            boolean has = false;
            for (AnfParam p : m.params()) {
                if ("txPreimage".equals(p.name()) && SHP.equals(p.type())) has = true;
            }
            allHaveTx &= has;
        }
        boolean declared = false;
        for (AnfProperty p : props) {
            if ("txPreimage".equals(p.name())) declared = true;
        }
        r.implicitTx = publics > 0 && allHaveTx && !declared;
        for (AnfMethod m : methodList) {
            if ("constructor".equals(m.name())) continue;
            View mv = new View(m, r.implicitTx);
            r.visit(mv, m.body(), errors);
            if (m.isPublic()) {
                Set<String> done = r.mustChecked(m, java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>()));
                for (AnfParam p : m.params()) {
                    if (SHP.equals(p.type()) && !done.contains(p.name())) {
                        errors.add(PreimageChecked.message(m.name(), p.name()));
                    }
                }
            }
        }
        return errors;
    }

    /**
     * GK-BUG-015's shared text on the IR path: a repeated method name, refused
     * before anything looks a method up by name (the source validator refuses
     * it; {@code --ir} did not, so two bodies could share a name).
     */
    public static void checkUniqueMethodNames(List<AnfMethod> methods) {
        Set<String> seen = new HashSet<>();
        for (AnfMethod m : methods) {
            if (!seen.add(m.name())) {
                throw new RuntimeException("IR validation: method '" + m.name()
                    + "' is already declared in this contract and cannot be re-declared");
            }
        }
    }

    public static void check(List<AnfProperty> props, List<AnfMethod> methods) {
        List<String> errs = errors(props, methods);
        if (!errs.isEmpty()) throw new RuntimeException("IR validation: " + String.join("; ", errs));
    }
}
