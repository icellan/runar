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

    private static final int THEN = -1;
    private static final int ELSE = -2;
    private static final int BODY = -3;

    private static int[] child(int[] p, int i) {
        int[] out = java.util.Arrays.copyOf(p, p.length + 1);
        out[p.length] = i;
        return out;
    }

    /**
     * Is the binding at {@code def} in scope at {@code from}? Only if it sits
     * earlier in the same list or in a list enclosing it: stack lowering
     * resolves names by position, so a binding after (or beside) a use never
     * answers for it.
     */
    private static boolean visible(int[] def, int[] from) {
        int n = def.length;
        if (n == 0 || from.length < n) return false;
        for (int i = 0; i < n - 1; i++) if (def[i] != from[i]) return false;
        return def[n - 1] < from[n - 1];
    }

    private record Def(AnfValue value, int[] path) {}

    private static final class View {
        final Map<String, Def> defs = new HashMap<>();
        /** Bound more than once, or under a parameter's name: never resolves. */
        final Set<String> poisoned = new HashSet<>();
        final Set<String> shp = new HashSet<>();
        final boolean implicit;

        View(AnfMethod m, boolean implicitTx) {
            boolean own = false;
            for (AnfParam p : m.params()) {
                poisoned.add(p.name());
                if (SHP.equals(p.type())) shp.add(p.name());
                if ("txPreimage".equals(p.name())) own = true;
            }
            collect(m.body(), new int[0]);
            implicit = !m.isPublic() && implicitTx && !own;
        }

        void collect(List<AnfBinding> bs, int[] at) {
            List<AnfBinding> list = orEmpty(bs);
            for (int i = 0; i < list.size(); i++) {
                AnfBinding b = list.get(i);
                int[] path = child(at, i);
                if (defs.containsKey(b.name())) poisoned.add(b.name());
                defs.put(b.name(), new Def(b.value(), path));
                if (b.value() instanceof If iff) {
                    collect(iff.thenBranch(), child(path, THEN));
                    collect(iff.elseBranch(), child(path, ELSE));
                } else if (b.value() instanceof Loop loop) {
                    collect(loop.body(), child(path, BODY));
                }
            }
        }

        Def lookup(String name, int[] from) {
            if (name == null || poisoned.contains(name)) return null;
            Def d = defs.get(name);
            return d != null && visible(d.path(), from) ? d : null;
        }

        String resolve(String name, int[] from) {
            for (int hops = 0; hops <= defs.size(); hops++) {
                Def d = lookup(name, from);
                if (d == null) return null;
                AnfValue v = d.value();
                if (v instanceof LoadParam lp) {
                    if (shp.contains(lp.name())) return lp.name();
                    return implicit && "txPreimage".equals(lp.name()) ? lp.name() : null;
                }
                if (v instanceof LoadProp lp) return implicit && "txPreimage".equals(lp.name()) ? lp.name() : null;
                name = refTarget(v);
                from = d.path();
            }
            return null;
        }

        Set<String> truthOf(String name, int[] from, int depth) {
            Def d = lookup(name, from);
            return d == null ? new HashSet<>() : truthValue(d.value(), d.path(), depth);
        }

        Set<String> truthValue(AnfValue v, int[] path, int depth) {
            if (depth > defs.size()) return new HashSet<>();
            if (v instanceof CheckPreimage cp) {
                String o = resolve(cp.preimage(), path);
                return o == null ? new HashSet<>() : new HashSet<>(Set.of(o));
            }
            if (v instanceof LoadConst lc) {
                if (lc.value() instanceof BoolConst bc && !bc.value()) return null;
                String next = refTarget(v);
                return next == null ? new HashSet<>() : truthOf(next, path, depth + 1);
            }
            if (v instanceof If iff) {
                List<AnfBinding> t = orEmpty(iff.thenBranch());
                List<AnfBinding> e = orEmpty(iff.elseBranch());
                if ((iff.results() != null && !iff.results().isEmpty()) || t.isEmpty() || e.isEmpty()) {
                    return new HashSet<>();
                }
                int nt = t.size() - 1;
                int ne = e.size() - 1;
                Set<String> both = union(truthOf(iff.cond(), path, depth + 1),
                    truthValue(t.get(nt).value(), child(child(path, THEN), nt), depth + 1));
                return intersect(both, truthValue(e.get(ne).value(), child(child(path, ELSE), ne), depth + 1));
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
        Set<String> result = walk(mv, m.body(), new int[0], new HashSet<>(), inner);
        memo.put(m, result);
        return result;
    }

    private Set<String> walk(View mv, List<AnfBinding> bs, int[] at, Set<String> doneIn, Set<AnfMethod> inner) {
        Set<String> done = new HashSet<>(doneIn);
        List<AnfBinding> list = orEmpty(bs);
        for (int bi = 0; bi < list.size(); bi++) {
            AnfValue v = list.get(bi).value();
            int[] path = child(at, bi);
            if (v instanceof Assert a) {
                Set<String> c = mv.truthOf(a.value(), path, 0);
                if (c != null) done.addAll(c);
            } else if (v instanceof If iff) {
                Set<String> t = walk(mv, iff.thenBranch(), child(path, THEN), done, inner);
                Set<String> e = walk(mv, iff.elseBranch(), child(path, ELSE), done, inner);
                t.retainAll(e);
                done = t;
            } else if (v instanceof MethodCall mc) {
                AnfMethod target = privates.get(mc.method());
                if (target != null) {
                    Set<String> checked = mustChecked(target, inner);
                    List<String> args = mc.args() == null ? List.of() : mc.args();
                    for (int i = 0; i < target.params().size() && i < args.size(); i++) {
                        if (!checked.contains(target.params().get(i).name())) continue;
                        String o = mv.resolve(args.get(i), path);
                        if (o != null) done.add(o);
                    }
                }
            }
        }
        return done;
    }

    private void visit(View mv, List<AnfBinding> bs, int[] at, List<String> errors) {
        List<AnfBinding> list = orEmpty(bs);
        for (int bi = 0; bi < list.size(); bi++) {
            AnfValue v = list.get(bi).value();
            int[] path = child(at, bi);
            if (v instanceof Call c && ExtractorPreimage.EXTRACTORS.contains(c.func())) {
                List<String> args = c.args() == null ? List.of() : c.args();
                if (mv.resolve(args.isEmpty() ? null : args.get(0), path) == null) {
                    errors.add(ExtractorPreimage.message(c.func()));
                }
            } else if (v instanceof MethodCall mc) {
                AnfMethod target = privates.get(mc.method());
                if (target != null) {
                    List<String> args = mc.args() == null ? List.of() : mc.args();
                    for (int i = 0; i < target.params().size(); i++) {
                        if (!SHP.equals(target.params().get(i).type())) continue;
                        if (i >= args.size() || mv.resolve(args.get(i), path) == null) {
                            errors.add(ExtractorPreimage.message(target.name()));
                            break;
                        }
                    }
                }
            } else if (v instanceof If iff) {
                visit(mv, iff.thenBranch(), child(path, THEN), errors);
                visit(mv, iff.elseBranch(), child(path, ELSE), errors);
            } else if (v instanceof Loop loop) {
                visit(mv, loop.body(), child(path, BODY), errors);
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
            r.visit(mv, m.body(), new int[0], errors);
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
