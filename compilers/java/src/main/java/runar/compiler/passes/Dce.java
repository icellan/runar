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
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.DeserializeState;
import runar.compiler.ir.anf.GetStateScript;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.RawScript;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.UnknownAnfKindError;
import runar.compiler.ir.anf.UpdateProp;

/**
 * Dead Code Elimination pass for ANF IR.
 *
 * <p>Removes bindings whose results are never referenced by other bindings,
 * preserving bindings with observable side effects (assert, update_prop,
 * check_preimage, add_output, add_raw_output, add_data_output, call,
 * method_call, raw_script). Iterates to a fixed point so transitively
 * dead bindings are also removed.
 *
 * <p>"Results" is plural on purpose (N-140). A binding does not only define
 * its own {@code name}: an {@code if} that merges branch locals also defines
 * every name in {@code results}, and both an {@code if} and a {@code loop}
 * define the names their nested bindings bind. Liveness used to test
 * {@code used.contains(b.name())} alone, so an {@code if} named {@code t9}
 * carrying {@code results ["a","b"]} — a name nothing ever references,
 * because callers reference {@code a} and {@code b} — was deleted whenever its
 * arms happened to be pure, and the merged locals kept their pre-branch
 * values. See {@code conformance/dce/live-if.test.ts}.
 *
 * <p>This module is the canonical, standalone DCE pass for the Java
 * compiler. It mirrors the Zig reference implementation in
 * {@code compilers/zig/src/passes/dce.zig}. The earlier inline
 * implementation in {@code AnfOptimize.java} has been surgically
 * extracted here.
 *
 * <p>Behaviour: byte-for-byte identical, at the time of that extraction, to
 * the previous inline DCE in {@code AnfOptimize.java}. Verified by the
 * conformance suite (cross-tier hex parity) and the unknown-kind
 * exhaustiveness tests.
 *
 * <p>N-140 is the one deliberate behaviour change since: liveness considers
 * the names a binding DEFINES, not only its own {@code name}.
 */
public final class Dce {

    private Dce() {}

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /** Eliminate dead bindings across every method in the program. */
    public static AnfProgram run(AnfProgram program) {
        List<AnfMethod> newMethods = new ArrayList<>(program.methods().size());
        for (AnfMethod m : program.methods()) {
            List<AnfBinding> cleaned = eliminateDead(m.body());
            newMethods.add(new AnfMethod(m.name(), m.params(), cleaned, m.isPublic()));
        }
        return new AnfProgram(program.contractName(), program.properties(), newMethods);
    }

    /**
     * Remove bindings whose results are never referenced. Public for
     * delegation from {@link AnfOptimize} which still calls this during
     * the EC rewrite's post-cleanup phase.
     */
    public static List<AnfBinding> eliminateDead(List<AnfBinding> body) {
        List<AnfBinding> current = body;
        while (true) {
            List<Set<String>> ownRefs = new ArrayList<>(current.size());
            Map<String, Integer> refCount = new HashMap<>();
            for (AnfBinding b : current) {
                Set<String> own = new HashSet<>();
                collectRefs(b.value(), own);
                ownRefs.add(own);
                for (String name : own) refCount.merge(name, 1, Integer::sum);
            }

            List<AnfBinding> kept = new ArrayList<>(current.size());
            boolean removed = false;
            for (int i = 0; i < current.size(); i++) {
                AnfBinding b = current.get(i);
                if (isReferencedExternally(b, ownRefs.get(i), refCount) || hasSideEffect(b.value())) {
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
     * Every SSA name a binding brings into scope: its own {@code name}, plus —
     * for the two nesting kinds — an {@code if}'s declared {@code results} (the
     * merged branch locals / property slots both arms leave behind) and the
     * names bound inside {@code then}, {@code else} and a {@code loop} body,
     * recursively.
     *
     * <p>{@code iterVar} is deliberately absent: it is the loop's own induction
     * variable, referenced only from inside the body, so counting it as defined
     * would make every non-trivial loop unconditionally live.
     */
    public static void collectDefinedNames(AnfBinding binding, Set<String> out) {
        out.add(binding.name());
        AnfValue v = binding.value();
        if (v instanceof If ifv) {
            for (String r : orEmpty(ifv.results())) out.add(r);
            for (AnfBinding b : orEmpty(ifv.thenBranch())) collectDefinedNames(b, out);
            for (AnfBinding b : orEmpty(ifv.elseBranch())) collectDefinedNames(b, out);
        } else if (v instanceof Loop loop) {
            for (AnfBinding b : orEmpty(loop.body())) collectDefinedNames(b, out);
        }
    }

    /**
     * Is any name this binding defines referenced by some OTHER binding?
     *
     * <p>{@code refCount} maps a name to the number of DISTINCT bindings
     * referencing it; {@code ownRefs} is this binding's own contribution.
     * Subtracting it is what keeps the rule from degenerating into "never
     * delete an {@code if} or a {@code loop}": an arm's bindings almost always
     * reference each other, and counting those self-references would make
     * every nesting node immortal.
     *
     * <p>For a non-nesting binding this is exactly the old
     * {@code used.contains(b.name())}: ANF has no self-reference, so
     * {@code ownRefs} never holds the binding's own name.
     */
    private static boolean isReferencedExternally(
        AnfBinding binding, Set<String> ownRefs, Map<String, Integer> refCount) {
        Set<String> defined = new HashSet<>();
        collectDefinedNames(binding, defined);
        for (String name : defined) {
            int external = refCount.getOrDefault(name, 0) - (ownRefs.contains(name) ? 1 : 0);
            if (external > 0) return true;
        }
        return false;
    }

    // ---------------------------------------------------------------
    // Core algorithm
    // ---------------------------------------------------------------

    /**
     * Collect every binding name referenced (transitively) by a value.
     * Mirrors {@code _collect_refs} in
     * {@code compilers/python/runar_compiler/frontend/dce.py}.
     */
    public static void collectRefs(AnfValue v, Set<String> used) {
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
            return;
        }
        if (v instanceof RawScript) {
            // Opaque byte span — no SSA operand refs.
            return;
        }
        // Exhaustiveness guard. Silently returning here would let DCE drop a
        // live binding because its refs went uncollected.
        throw new UnknownAnfKindError(v.kind(), "anf-optimize.collectRefs");
    }

    /**
     * Side-effect predicate. Mirrors the Python {@code _has_side_effect} list:
     * assert, update_prop, check_preimage, deserialize_state, add_output,
     * add_raw_output, add_data_output, if, loop, call, method_call.
     */
    public static boolean hasSideEffect(AnfValue v) {
        if (v instanceof Assert
            || v instanceof UpdateProp
            || v instanceof CheckPreimage
            || v instanceof DeserializeState
            || v instanceof AddOutput
            || v instanceof AddRawOutput
            || v instanceof AddDataOutput
            || v instanceof Call
            || v instanceof MethodCall
            || v instanceof RawScript) { // opaque byte span — DCE must never eliminate it
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
        // Issue #109 (@embedAlways): a load_prop injected to force a readonly
        // field into the deployed locking script carries `preserve = true`, so
        // DCE must keep it even though nothing references it. Ordinary
        // load_props (preserve = false) remain freely eliminable. Mirrors
        // compilers/zig/src/passes/dce.zig.
        if (v instanceof LoadProp lp) {
            return lp.preserve();
        }
        // Pure values — safe for DCE to drop when unreferenced.
        if (v instanceof LoadParam
            || v instanceof LoadConst
            || v instanceof GetStateScript
            || v instanceof BinOp
            || v instanceof UnaryOp
            || v instanceof ArrayLiteral) {
            return false;
        }
        // Exhaustiveness guard. A silent `return false;` would cause DCE to
        // eliminate a new side-effecting ANF kind, producing scripts that
        // omit observable behavior.
        throw new UnknownAnfKindError(v.kind(), "anf-optimize.hasSideEffect");
    }

    private static <T> List<T> orEmpty(List<T> list) {
        return list == null ? List.of() : list;
    }
}
