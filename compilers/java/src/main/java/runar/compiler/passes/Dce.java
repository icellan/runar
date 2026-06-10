package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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
 * <p>This module is the canonical, standalone DCE pass for the Java
 * compiler. It mirrors the Zig reference implementation in
 * {@code compilers/zig/src/passes/dce.zig}. The earlier inline
 * implementation in {@code AnfOptimize.java} has been surgically
 * extracted here.
 *
 * <p>Behaviour: byte-for-byte identical to the previous inline DCE in
 * {@code AnfOptimize.java}. Verified by the conformance suite (cross-tier
 * hex parity) and the unknown-kind exhaustiveness tests.
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
        // Pure values — safe for DCE to drop when unreferenced.
        if (v instanceof LoadParam
            || v instanceof LoadProp
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
