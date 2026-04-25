package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AddDataOutput;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AddRawOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.ArrayLiteral;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.ConstValue;
import runar.compiler.ir.anf.DeserializeState;
import runar.compiler.ir.anf.GetStateScript;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;

/**
 * General ANF cleanup pass (Pass 4.5 in the Java pipeline).
 *
 * <p>Runs after {@link ConstantFold} and applies three transformations,
 * iterated to a fixed point:
 *
 * <ol>
 *   <li><b>Tautological-branch removal.</b> If the condition of an
 *       {@code If} binding folded to a literal {@code true}/{@code false},
 *       splice the surviving branch in place of the {@code If} value
 *       (after any constant-folding pass marks the dead branch as empty).</li>
 *   <li><b>Constant propagation through aliases.</b> Bindings of the form
 *       {@code t_i = load_const "@ref:t_j"} are rewritten by replacing
 *       references to {@code t_i} with {@code t_j} (matching how the EC
 *       optimizer encodes aliases).</li>
 *   <li><b>Dead-binding elimination.</b> Iteratively remove any
 *       {@code let}-binding whose name is never referenced and whose RHS
 *       has no side effects.  Side effects mirror the Python
 *       {@code _has_side_effect} set: {@code assert}, {@code update_prop},
 *       {@code check_preimage}, {@code deserialize_state}, {@code add_output},
 *       {@code add_raw_output}, {@code add_data_output}, plus {@code if},
 *       {@code loop}, {@code call}, and {@code method_call} (call kinds may
 *       transitively perform crypto / output ops).</li>
 * </ol>
 *
 * <p>This pass is unconditional in the pipeline (no CLI flag), matching the
 * Python reference.
 */
public final class AnfOptimize {

    private AnfOptimize() {}

    public static AnfProgram run(AnfProgram program) {
        // The TypeScript / Python references do not run generic alias
        // propagation or dead-binding elimination at this stage of the
        // pipeline — local-name aliases (`result -> @ref:t2`) and unused
        // bindings stay in the ANF IR until stack lowering handles them.
        // Removing them here would diverge from the canonical ANF, so this
        // pass is currently an identity transformation.
        //
        // The previously-implemented tautological-if collapse and alias
        // propagation are intentionally disabled to preserve byte-identical
        // ANF parity with the other tiers. The transformation helpers
        // remain in this file for the future EC/optimizer pass that will
        // mirror Python's `anf_optimize.py` (EC algebraic simplification),
        // which is scoped behind the `--disable-constant-folding` flag and
        // therefore inert under conformance runs.
        return program;
    }

    @SuppressWarnings("unused")
    private static AnfProgram runFullOptimizer(AnfProgram program) {
        List<AnfMethod> opts = new ArrayList<>(program.methods().size());
        for (AnfMethod m : program.methods()) {
            opts.add(optimizeMethod(m));
        }
        return new AnfProgram(program.contractName(), program.properties(), opts);
    }

    private static AnfMethod optimizeMethod(AnfMethod method) {
        List<AnfBinding> body = method.body();

        // Iterate to fixed point: each pass may unblock further optimizations.
        for (int i = 0; i < 64; i++) {
            int before = bodyFingerprint(body);

            body = collapseTautologicalIfs(body);
            body = propagateAliases(body);
            body = eliminateDead(body);

            int after = bodyFingerprint(body);
            if (before == after) break;
        }

        return new AnfMethod(method.name(), method.params(), body, method.isPublic());
    }

    /** Cheap structural fingerprint used as a fixed-point sentinel. */
    private static int bodyFingerprint(List<AnfBinding> body) {
        int h = body.size();
        for (AnfBinding b : body) {
            h = h * 31 + b.name().hashCode();
            h = h * 31 + b.value().getClass().getName().hashCode();
            h = h * 31 + valueShapeHash(b.value());
        }
        return h;
    }

    private static int valueShapeHash(AnfValue v) {
        if (v instanceof If ifv) {
            return 17 + (ifv.cond() == null ? 0 : ifv.cond().hashCode())
                + 31 * (ifv.thenBranch() == null ? 0 : ifv.thenBranch().size())
                + 31 * (ifv.elseBranch() == null ? 0 : ifv.elseBranch().size());
        }
        if (v instanceof Loop lp) {
            return 19 + lp.count() + 31 * (lp.body() == null ? 0 : lp.body().size());
        }
        if (v instanceof LoadConst lc) {
            return lc.value() == null ? 0 : lc.value().hashCode();
        }
        return v.kind().hashCode();
    }

    // ---------------------------------------------------------------
    // 1. Tautological-branch removal
    // ---------------------------------------------------------------

    /**
     * If a binding {@code t = if(cond) {then} else {else}} has both branches
     * after constant-folding such that exactly one is non-empty, splice that
     * branch into the surrounding body, dropping the {@code If} wrapper.
     *
     * <p>This makes constant folding visible across the ANF pipeline:
     * after this pass, {@code if (true) { ... }} becomes a flat block.
     * Note that we only collapse when the surviving branch ends in a
     * binding whose name we can map back to {@code t}.  If the branch is
     * empty (both then and else, e.g. when both bodies were entirely dead),
     * we drop the binding outright.
     */
    private static List<AnfBinding> collapseTautologicalIfs(List<AnfBinding> body) {
        List<AnfBinding> out = new ArrayList<>(body.size());
        for (AnfBinding b : body) {
            if (b.value() instanceof If ifv) {
                List<AnfBinding> then = orEmpty(ifv.thenBranch());
                List<AnfBinding> els = orEmpty(ifv.elseBranch());

                // Recurse into surviving branches first.
                List<AnfBinding> thenOpt = collapseTautologicalIfs(then);
                List<AnfBinding> elsOpt = collapseTautologicalIfs(els);

                boolean thenEmpty = thenOpt.isEmpty();
                boolean elsEmpty = elsOpt.isEmpty();

                if (thenEmpty && elsEmpty) {
                    // Whole branch evaporated; binding is dead. Skip.
                    continue;
                }
                if (thenEmpty ^ elsEmpty) {
                    // Exactly one branch survived — splice it in place of the If.
                    List<AnfBinding> surviving = thenEmpty ? elsOpt : thenOpt;
                    out.addAll(surviving);
                    continue;
                }
                // Both branches non-empty: keep the If, but with optimized children.
                out.add(new AnfBinding(b.name(), new If(ifv.cond(), thenOpt, elsOpt), b.sourceLoc()));
                continue;
            }
            if (b.value() instanceof Loop lp) {
                List<AnfBinding> bodyOpt = collapseTautologicalIfs(orEmpty(lp.body()));
                out.add(new AnfBinding(b.name(), new Loop(lp.count(), bodyOpt, lp.iterVar()), b.sourceLoc()));
                continue;
            }
            out.add(b);
        }
        return out;
    }

    // ---------------------------------------------------------------
    // 2. Constant propagation through @ref: aliases
    // ---------------------------------------------------------------

    /**
     * Walk the body and build a rename map {@code t_i -> canonical(t_j)}
     * for every binding {@code t_i = load_const "@ref:t_j"}.  Then rewrite
     * every reference to {@code t_i} (as a left/right/operand/cond/arg/...)
     * to point at {@code canonical(t_j)} instead.  After this pass, alias
     * bindings have no consumers and are picked up by DCE.
     */
    private static List<AnfBinding> propagateAliases(List<AnfBinding> body) {
        Map<String, String> rename = collectAliasRenames(body);
        if (rename.isEmpty()) return body;

        List<AnfBinding> out = new ArrayList<>(body.size());
        for (AnfBinding b : body) {
            out.add(new AnfBinding(b.name(), renameInValue(b.value(), rename), b.sourceLoc()));
        }
        return out;
    }

    private static Map<String, String> collectAliasRenames(List<AnfBinding> body) {
        Map<String, String> direct = new HashMap<>();
        for (AnfBinding b : body) {
            if (b.value() instanceof LoadConst lc && lc.value() instanceof BytesConst bs) {
                String hex = bs.hex();
                if (hex != null && hex.startsWith("@ref:")) {
                    direct.put(b.name(), hex.substring(5));
                }
            }
        }
        // Resolve transitively: t_i -> t_j -> t_k => t_i -> t_k.
        Map<String, String> resolved = new HashMap<>();
        for (String src : direct.keySet()) {
            String cur = src;
            Set<String> seen = new HashSet<>();
            while (direct.containsKey(cur)) {
                if (!seen.add(cur)) break;
                cur = direct.get(cur);
            }
            if (!cur.equals(src)) {
                resolved.put(src, cur);
            }
        }
        return resolved;
    }

    private static String resolve(String name, Map<String, String> rename) {
        String r = rename.get(name);
        return r == null ? name : r;
    }

    private static List<String> resolveAll(List<String> args, Map<String, String> rename) {
        if (args == null) return null;
        List<String> out = new ArrayList<>(args.size());
        for (String a : args) out.add(resolve(a, rename));
        return out;
    }

    private static AnfValue renameInValue(AnfValue v, Map<String, String> rename) {
        if (v instanceof LoadParam || v instanceof LoadProp || v instanceof GetStateScript) {
            return v;
        }
        if (v instanceof LoadConst) return v;
        if (v instanceof BinOp b) {
            return new BinOp(b.op(), resolve(b.left(), rename), resolve(b.right(), rename), b.resultType());
        }
        if (v instanceof UnaryOp u) {
            return new UnaryOp(u.op(), resolve(u.operand(), rename), u.resultType());
        }
        if (v instanceof Call c) {
            return new Call(c.func(), resolveAll(c.args(), rename));
        }
        if (v instanceof MethodCall mc) {
            return new MethodCall(resolve(mc.object(), rename), mc.method(), resolveAll(mc.args(), rename));
        }
        if (v instanceof If ifv) {
            return new If(resolve(ifv.cond(), rename),
                renameInBody(orEmpty(ifv.thenBranch()), rename),
                renameInBody(orEmpty(ifv.elseBranch()), rename));
        }
        if (v instanceof Loop lp) {
            return new Loop(lp.count(), renameInBody(orEmpty(lp.body()), rename), lp.iterVar());
        }
        if (v instanceof Assert a) {
            return new Assert(resolve(a.value(), rename));
        }
        if (v instanceof UpdateProp up) {
            return new UpdateProp(up.name(), resolve(up.value(), rename));
        }
        if (v instanceof CheckPreimage cp) {
            return new CheckPreimage(resolve(cp.preimage(), rename));
        }
        if (v instanceof DeserializeState ds) {
            return new DeserializeState(resolve(ds.preimage(), rename));
        }
        if (v instanceof AddOutput ao) {
            return new AddOutput(resolve(ao.satoshis(), rename),
                resolveAll(ao.stateValues(), rename),
                resolve(ao.preimage(), rename));
        }
        if (v instanceof AddRawOutput ar) {
            return new AddRawOutput(resolve(ar.satoshis(), rename), resolve(ar.scriptBytes(), rename));
        }
        if (v instanceof AddDataOutput ad) {
            return new AddDataOutput(resolve(ad.satoshis(), rename), resolve(ad.scriptBytes(), rename));
        }
        if (v instanceof ArrayLiteral al) {
            return new ArrayLiteral(resolveAll(al.elements(), rename));
        }
        return v;
    }

    private static List<AnfBinding> renameInBody(List<AnfBinding> body, Map<String, String> rename) {
        List<AnfBinding> out = new ArrayList<>(body.size());
        for (AnfBinding b : body) {
            out.add(new AnfBinding(b.name(), renameInValue(b.value(), rename), b.sourceLoc()));
        }
        return out;
    }

    // ---------------------------------------------------------------
    // 3. Dead-binding elimination
    // ---------------------------------------------------------------

    private static List<AnfBinding> eliminateDead(List<AnfBinding> body) {
        List<AnfBinding> current = body;
        while (true) {
            Set<String> used = new HashSet<>();
            for (AnfBinding b : current) collectRefs(b.value(), used);

            List<AnfBinding> kept = new ArrayList<>(current.size());
            boolean removed = false;
            for (AnfBinding b : current) {
                if (used.contains(b.name()) || hasSideEffect(b.value())) {
                    kept.add(b);
                } else {
                    removed = true;
                }
            }
            if (!removed) return kept;
            current = kept;
        }
    }

    /**
     * Collect every binding name referenced (transitively) by a value.
     * Mirrors {@code _collect_refs} in
     * {@code compilers/python/runar_compiler/frontend/anf_optimize.py}.
     */
    private static void collectRefs(AnfValue v, Set<String> used) {
        if (v instanceof LoadParam || v instanceof LoadProp || v instanceof GetStateScript) {
            return;
        }
        if (v instanceof LoadConst lc) {
            // Track @ref: aliases as references so we don't DCE their target.
            if (lc.value() instanceof BytesConst bs) {
                String hex = bs.hex();
                if (hex != null && hex.startsWith("@ref:")) {
                    used.add(hex.substring(5));
                }
            }
            return;
        }
        if (v instanceof BinOp b) {
            used.add(b.left());
            used.add(b.right());
            return;
        }
        if (v instanceof UnaryOp u) {
            used.add(u.operand());
            return;
        }
        if (v instanceof Call c) {
            if (c.args() != null) used.addAll(c.args());
            return;
        }
        if (v instanceof MethodCall mc) {
            used.add(mc.object());
            if (mc.args() != null) used.addAll(mc.args());
            return;
        }
        if (v instanceof If ifv) {
            used.add(ifv.cond());
            for (AnfBinding tb : orEmpty(ifv.thenBranch())) collectRefs(tb.value(), used);
            for (AnfBinding eb : orEmpty(ifv.elseBranch())) collectRefs(eb.value(), used);
            return;
        }
        if (v instanceof Loop lp) {
            for (AnfBinding lb : orEmpty(lp.body())) collectRefs(lb.value(), used);
            return;
        }
        if (v instanceof Assert a) {
            used.add(a.value());
            return;
        }
        if (v instanceof UpdateProp up) {
            used.add(up.value());
            return;
        }
        if (v instanceof CheckPreimage cp) {
            used.add(cp.preimage());
            return;
        }
        if (v instanceof DeserializeState ds) {
            used.add(ds.preimage());
            return;
        }
        if (v instanceof AddOutput ao) {
            if (ao.satoshis() != null) used.add(ao.satoshis());
            if (ao.stateValues() != null) used.addAll(ao.stateValues());
            if (ao.preimage() != null) used.add(ao.preimage());
            return;
        }
        if (v instanceof AddRawOutput ar) {
            if (ar.satoshis() != null) used.add(ar.satoshis());
            if (ar.scriptBytes() != null) used.add(ar.scriptBytes());
            return;
        }
        if (v instanceof AddDataOutput ad) {
            if (ad.satoshis() != null) used.add(ad.satoshis());
            if (ad.scriptBytes() != null) used.add(ad.scriptBytes());
            return;
        }
        if (v instanceof ArrayLiteral al) {
            if (al.elements() != null) used.addAll(al.elements());
        }
    }

    /**
     * Side-effect predicate. Mirrors the Python {@code _has_side_effect} list:
     * assert, update_prop, check_preimage, deserialize_state, add_output,
     * add_raw_output, add_data_output, if, loop, call, method_call.
     */
    private static boolean hasSideEffect(AnfValue v) {
        if (v instanceof Assert
            || v instanceof UpdateProp
            || v instanceof CheckPreimage
            || v instanceof DeserializeState
            || v instanceof AddOutput
            || v instanceof AddRawOutput
            || v instanceof AddDataOutput
            || v instanceof Call
            || v instanceof MethodCall) {
            return true;
        }
        if (v instanceof If ifv) {
            for (AnfBinding tb : orEmpty(ifv.thenBranch())) {
                if (hasSideEffect(tb.value())) return true;
            }
            for (AnfBinding eb : orEmpty(ifv.elseBranch())) {
                if (hasSideEffect(eb.value())) return true;
            }
            return false;
        }
        if (v instanceof Loop lp) {
            for (AnfBinding lb : orEmpty(lp.body())) {
                if (hasSideEffect(lb.value())) return true;
            }
            return false;
        }
        return false;
    }

    private static <T> List<T> orEmpty(List<T> list) {
        return list == null ? List.of() : list;
    }
}
