package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AddDataOutput;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AddRawOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfProperty;
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
import runar.compiler.ir.anf.RawScript;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.UnknownAnfKindError;

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
 * <p>F-275: despite the paragraph above, this pass is NOT unconditional.
 * {@link #run} returns the program UNCHANGED when no method contains an EC
 * intrinsic call ({@code hasEcCalls} / the {@code anyChanged} gate below) —
 * so none of the three transformations above, dead-binding elimination
 * included, touch a non-EC program. Go's {@code anf_optimize.go} and
 * Python's {@code anf_optimize.py} ({@code _has_ec_calls}) gate the same
 * way, so this is cross-tier architecture, not a Java-only oversight. See
 * {@code F275DceInvocationTest} for the pinned current behaviour.
 */
public final class AnfOptimize {

    private AnfOptimize() {}

    /**
     * EC algebraic optimizer (Pass 4.5). Mirrors
     * {@code compilers/python/runar_compiler/frontend/anf_optimize.py}
     * line-for-line: 12 algebraic-simplification rules over secp256k1
     * intrinsic calls, iterated to a fixed point per method, followed by
     * dead-binding elimination.
     *
     * <p>The pass is gated: programs with no EC calls are returned
     * unchanged so non-EC fixtures remain byte-identical with the other
     * tiers' canonical ANF.
     */
    public static AnfProgram run(AnfProgram program) {
        boolean anyChanged = false;
        for (AnfMethod m : program.methods()) {
            if (hasEcCalls(m.body())) {
                anyChanged = true;
                break;
            }
        }
        if (!anyChanged) return program;

        // N-097 / N-195: the hasEcCalls check above is only a fast path (a
        // rule can only fire on an EC call, at any depth since N-201). The DCE gate is the TS
        // reference's (anf-ec.ts optimizeEC): dead-binding elimination runs
        // over EVERY method iff a rewrite fired in ANY method; otherwise the
        // program is returned untouched, dead bindings included.
        boolean fired = false;
        List<AnfMethod> opts = new ArrayList<>(program.methods().size());
        for (AnfMethod m : program.methods()) {
            AnfMethod o = optimizeEcMethod(m, program.properties());
            if (o != m) fired = true;
            opts.add(o);
        }
        if (!fired) return program;

        List<AnfMethod> cleaned = new ArrayList<>(opts.size());
        for (int i = 0; i < opts.size(); i++) {
            AnfMethod method = opts.get(i);
            AnfMethod dced = method.withBody(eliminateDead(method));
            // N-201: a rewrite inside an if arm or a loop body orphans its
            // operands there, and the DCE above filters only the top level;
            // an orphan left in an arm unbalances the arms (the N-446
            // hazard). Same candidate rule as the constant folder's prune:
            // only names the method referenced before this pass ran.
            Set<String> candidates = new HashSet<>();
            for (AnfBinding b : program.methods().get(i).body()) Dce.collectRefs(b.value(), candidates);
            AnfMethod pruned = dced.withBody(Dce.eliminateDeadAmong(dced, candidates));
            // N-113: drop the inner ecMul/ecMulGen calls a fusion orphaned
            // whose abort is still performed, then prune what that orphans.
            for (;;) {
                List<AnfBinding> next = removeGateSubsumedEcCalls(pruned, candidates);
                if (next == null) break;
                AnfMethod m2 = pruned.withBody(next);
                pruned = m2.withBody(Dce.eliminateDeadAmong(m2, candidates));
            }
            cleaned.add(pruned);
        }
        return program.withMethods(cleaned);
    }

    /**
     * N-113 (the TS reference's anf-ec.ts {@code removeGateSubsumedEcCalls}):
     * remove dead scalar multiplications whose only effect, a possible abort,
     * is provably still performed. Returns the new body, or {@code null} when
     * nothing was removed.
     *
     * <ul>
     *   <li>{@code ecMulGen(<const k>)} cannot abort: its point is the fixed
     *       generator, which passes ecMul's operand gate, and the ladder
     *       reduces any k.</li>
     *   <li>{@code ecMul(q, <const k>)} aborts exactly when its operand gate
     *       {@code q === O || ecOnCurve(q)} fails (R-157). It may go when a
     *       WITNESS performs the same gate: another {@code ecMul(q', _)}, q'
     *       the same binding as q (F-269), not itself removable, in the same
     *       scope or an ENCLOSING one — never a nested one, which runs only
     *       on some paths.</li>
     *   <li>{@code ecNegate} is never removed: R7, R8 and R8r rely on it as a
     *       gate.</li>
     * </ul>
     *
     * <p>Only a removal candidate goes (a name referenced before the EC pass
     * ran — the inner call a fusion orphaned), referenced nowhere in the
     * method now, not a private method's return value (F-108) and not one of
     * its if's results.
     */
    private static List<AnfBinding> removeGateSubsumedEcCalls(AnfMethod method, Set<String> candidates) {
        ValueMap vm = new ValueMap(collectReboundNames(method));
        Set<String> refs = new HashSet<>();
        indexForRemoval(orEmpty(method.body()), vm, refs);
        boolean keepLast = !"constructor".equals(method.name()) && !method.isPublic();
        return filterSubsumed(orEmpty(method.body()), List.of(), Set.of(), true, keepLast, vm, refs, candidates);
    }

    private static void indexForRemoval(List<AnfBinding> bindings, ValueMap vm, Set<String> refs) {
        for (AnfBinding b : bindings) {
            vm.put(b.name(), b.value());
            Dce.collectRefs(b.value(), refs);
            if (b.value() instanceof If ifv) {
                indexForRemoval(orEmpty(ifv.thenBranch()), vm, refs);
                indexForRemoval(orEmpty(ifv.elseBranch()), vm, refs);
            } else if (b.value() instanceof Loop lp) {
                indexForRemoval(orEmpty(lp.body()), vm, refs);
            }
        }
    }

    private static boolean removableEcCall(AnfBinding b, Set<String> protect, boolean isReturn,
                                           ValueMap vm, Set<String> refs, Set<String> candidates) {
        if (!(b.value() instanceof Call c) || isReturn || !candidates.contains(b.name())
            || refs.contains(b.name()) || protect.contains(b.name())) {
            return false;
        }
        List<String> args = orEmpty(c.args());
        if ("ecMulGen".equals(c.func())) {
            return args.size() == 1 && getConstInt(args.get(0), vm) != null;
        }
        if ("ecMul".equals(c.func())) {
            return args.size() == 2 && getConstInt(args.get(1), vm) != null && stable(args.get(0), vm);
        }
        return false;
    }

    private static List<AnfBinding> filterSubsumed(List<AnfBinding> bindings, List<String> outer,
                                                   Set<String> protect, boolean topLevel, boolean keepLast,
                                                   ValueMap vm, Set<String> refs, Set<String> candidates) {
        int n = bindings.size();
        boolean[] isCand = new boolean[n];
        for (int i = 0; i < n; i++) {
            isCand[i] = removableEcCall(bindings.get(i), protect, topLevel && keepLast && i == n - 1,
                vm, refs, candidates);
        }
        List<String> witnesses = new ArrayList<>(outer);
        for (int i = 0; i < n; i++) {
            if (!isCand[i] && bindings.get(i).value() instanceof Call c && "ecMul".equals(c.func())
                && orEmpty(c.args()).size() == 2) {
                String w = canonical(c.args().get(0), vm);
                if (w != null) witnesses.add(w);
            }
        }
        boolean changed = false;
        List<AnfBinding> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            AnfBinding b = bindings.get(i);
            AnfValue v = b.value();
            if (isCand[i] && v instanceof Call c
                && ("ecMulGen".equals(c.func()) || witnesses.contains(canonical(c.args().get(0), vm)))) {
                changed = true;
                continue;
            }
            if (v instanceof If ifv) {
                Set<String> results = ifv.results() == null ? Set.of() : new HashSet<>(ifv.results());
                List<AnfBinding> t = filterSubsumed(orEmpty(ifv.thenBranch()), witnesses, results, false,
                    keepLast, vm, refs, candidates);
                List<AnfBinding> e = filterSubsumed(orEmpty(ifv.elseBranch()), witnesses, results, false,
                    keepLast, vm, refs, candidates);
                if (t != null || e != null) {
                    changed = true;
                    out.add(new AnfBinding(b.name(), new If(ifv.cond(),
                        t != null ? t : ifv.thenBranch(), e != null ? e : ifv.elseBranch(), ifv.results()),
                        b.sourceLoc()));
                    continue;
                }
            } else if (v instanceof Loop lp) {
                List<AnfBinding> body = filterSubsumed(orEmpty(lp.body()), witnesses, Set.of(), false,
                    keepLast, vm, refs, candidates);
                if (body != null) {
                    changed = true;
                    out.add(new AnfBinding(b.name(),
                        new Loop(lp.count(), body, lp.iterVar(), lp.start(), lp.step()), b.sourceLoc()));
                    continue;
                }
            }
            out.add(b);
        }
        return changed ? out : null;
    }

    // ===================================================================
    // EC algebraic optimizer (port of Python anf_optimize.py)
    // ===================================================================

    /** secp256k1 group order N. */
    private static final BigInteger CURVE_N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger GEN_X = new BigInteger(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger GEN_Y = new BigInteger(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static final String INFINITY_HEX;
    private static final String G_HEX;
    static {
        StringBuilder sb = new StringBuilder(128);
        for (int i = 0; i < 128; i++) sb.append('0');
        INFINITY_HEX = sb.toString();
        G_HEX = pad64(GEN_X) + pad64(GEN_Y);
    }

    private static String pad64(BigInteger v) {
        String hex = v.toString(16);
        StringBuilder out = new StringBuilder(64);
        for (int i = hex.length(); i < 64; i++) out.append('0');
        out.append(hex);
        return out.toString();
    }

    private static final Set<String> EC_FUNCS = Set.of(
        "ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecOnCurve",
        "ecModReduce", "ecEncodeCompressed", "ecMakePoint", "ecPointX", "ecPointY"
    );

    private static boolean hasEcCalls(List<AnfBinding> body) {
        for (AnfBinding b : body) {
            if (b.value() instanceof Call c && EC_FUNCS.contains(c.func())) return true;
            if (b.value() instanceof If ifv) {
                if (hasEcCalls(orEmpty(ifv.thenBranch()))) return true;
                if (hasEcCalls(orEmpty(ifv.elseBranch()))) return true;
            }
            if (b.value() instanceof Loop lp) {
                if (hasEcCalls(orEmpty(lp.body()))) return true;
            }
        }
        return false;
    }

    /**
     * Iteration bound for the EC rewrite fixed point (R-264). Exhausting it is
     * a refusal, not a quiet stop — see optimizeEcMethod.
     */
    private static final int EC_FIXED_POINT_LIMIT = 64;

    private static AnfMethod optimizeEcMethod(AnfMethod method, List<AnfProperty> properties) {
        // Fixed-point: each pass may unblock further optimizations (e.g. one
        // rule produces an aliased value that matches another rule).
        // R-264: the seven tiers do not agree on how many times to iterate.
        // The TypeScript reference makes ONE pass (optimizeMethodEC has no
        // outer loop at all); Go, Zig and Ruby loop to a fixed point with no
        // bound; this tier stops at 64. Cross-tier byte-identity survives that
        // only because one pass already reaches the fixed point for everything
        // in the corpus — if a second pass ever changed a program, TS would
        // diverge from Go/Zig/Ruby immediately, with or without this cap.
        //
        // The cap itself is not the hazard; stopping QUIETLY is. A program that
        // reached iteration 64 here would be emitted partially optimised while
        // the unbounded tiers kept going, and the two would disagree on bytes
        // with nothing said. So the bound is kept (an unbounded loop on a
        // non-converging rule set is its own failure) and exhausting it is now
        // a refusal.
        List<AnfBinding> body = new ArrayList<>(method.body());
        Set<String> usedNames = collectUsedNames(method, properties);
        // F-269: names bound more than once; alias resolution never passes one.
        Set<String> reboundNames = collectReboundNames(method);
        boolean converged = false;
        boolean fired = false;
        for (int iter = 0; iter < EC_FIXED_POINT_LIMIT; iter++) {
            // N-460: the fusion guard's referrer counts, once per sweep.
            Map<String, Integer> referrers = countReferrers(body, method);
            List<AnfBinding> next = optimizeBodyOnce(body, new ValueMap(reboundNames), null, usedNames,
                referrers, Set.of());
            boolean changed = next != null;
            if (next == null) next = body;
            body = next;
            if (!changed) {
                converged = true;
                break;
            }
            fired = true;
        }
        if (!converged) {
            throw new IllegalStateException(
                "EC optimiser did not reach a fixed point for method '" + method.name()
                    + "' within " + EC_FIXED_POINT_LIMIT + " iterations. The Go, Zig and "
                    + "Ruby tiers iterate without a bound and would keep going, so "
                    + "emitting this program here would diverge from them. Either the "
                    + "rule set does not converge for this input, or the limit is too "
                    + "low.");
        }
        // No rule fired: hand back the same method so run() can tell. Dead-
        // binding elimination is run()'s, over every method (N-097).
        return fired ? method.withBody(body) : method;
    }

    /**
     * One left-to-right sweep over a scope (the TS {@code optimizeBodyOnce}):
     * each binding is tried once against the values of the bindings before
     * it, as already rewritten in this sweep. N-201: it descends into if arms
     * (then before else) and loop bodies at the position of their binding,
     * each with its own scope ({@link ValueMap#nestedScope}); it used to visit
     * the top level only. Returns {@code null} when no rule fired.
     */
    private static List<AnfBinding> optimizeBodyOnce(List<AnfBinding> body, ValueMap outer, String hidden,
                                                     Set<String> usedNames, Map<String, Integer> referrers,
                                                     Set<String> outerFrame) {
        ValueMap valueMap = outer.nestedScope(hidden);
        // N-460: an if arm sees its enclosing frame, a loop body starts a new one.
        Set<String> local = new HashSet<>();
        for (AnfBinding b : body) local.add(b.name());
        Set<String> frame = new HashSet<>(outerFrame);
        frame.addAll(local);
        FusionScope scope = new FusionScope(referrers, local, frame);
        List<AnfBinding> next = new ArrayList<>(body.size());
        boolean changed = false;
        for (AnfBinding b : body) {
            valueMap.put(b.name(), b.value());
            if (b.value() instanceof If ifv) {
                List<AnfBinding> thenB = optimizeBodyOnce(orEmpty(ifv.thenBranch()), valueMap, null, usedNames,
                    referrers, frame);
                List<AnfBinding> elseB = optimizeBodyOnce(orEmpty(ifv.elseBranch()), valueMap, null, usedNames,
                    referrers, frame);
                if (thenB != null || elseB != null) {
                    If nv = new If(ifv.cond(),
                        thenB != null ? thenB : ifv.thenBranch(),
                        elseB != null ? elseB : ifv.elseBranch(),
                        ifv.results());
                    valueMap.put(b.name(), nv);
                    next.add(new AnfBinding(b.name(), nv, b.sourceLoc()));
                    changed = true;
                } else {
                    next.add(b);
                }
                continue;
            }
            if (b.value() instanceof Loop lp) {
                List<AnfBinding> bodyB = optimizeBodyOnce(orEmpty(lp.body()), valueMap, lp.iterVar(), usedNames,
                    referrers, Set.of());
                if (bodyB != null) {
                    Loop nv = new Loop(lp.count(), bodyB, lp.iterVar(), lp.start(), lp.step());
                    valueMap.put(b.name(), nv);
                    next.add(new AnfBinding(b.name(), nv, b.sourceLoc()));
                    changed = true;
                } else {
                    next.add(b);
                }
                continue;
            }
            int preludeStart = next.size();
            AnfValue optimized = tryOptimize(b.name(), b.value(), valueMap, next, usedNames, scope);
            AnfBinding rebound = b;
            if (optimized != null) {
                // N-218: every helper a rewrite mints (the N-104/N-251
                // gate bindings, the fused-scalar helper) takes the
                // rewritten binding's own sourceLoc, mirroring F-343 in
                // the TS reference (anf-ec.ts optimizeBodyOnce) — it
                // exists only because of that source expression, and
                // stack lowering maps opcodes through binding.sourceLoc.
                for (int i = preludeStart; i < next.size(); i++) {
                    AnfBinding h = next.get(i);
                    next.set(i, new AnfBinding(h.name(), h.value(), b.sourceLoc()));
                }
                rebound = new AnfBinding(b.name(), optimized, b.sourceLoc());
                changed = true;
            }
            valueMap.put(rebound.name(), rebound.value());
            next.add(rebound);
        }
        return changed ? next : null;
    }

    /**
     * F-086: every name the method already uses — binding names at any depth
     * (if/loop arms included), loop iteration variables, params, and the
     * contract's properties. A scalar-fusing rewrite mints a new binding; ANF
     * is single-assignment and stack lowering resolves a name to its
     * shallowest slot, so a minted name that is already in use silently
     * aliases the two values. {@code --ir} input chooses these names freely.
     */
    private static Set<String> collectUsedNames(AnfMethod method, List<AnfProperty> properties) {
        Set<String> used = new HashSet<>();
        for (AnfProperty p : orEmpty(properties)) used.add(p.name());
        for (AnfParam p : orEmpty(method.params())) used.add(p.name());
        collectBindingNames(orEmpty(method.body()), used);
        return used;
    }

    /**
     * Binding name to its current value, plus the method's rebound names
     * (F-269, see {@link #canonical}).
     */
    private static final class ValueMap extends LinkedHashMap<String, AnfValue> {
        private static final long serialVersionUID = 1L;
        final Set<String> rebound;

        ValueMap(Set<String> rebound) {
            this.rebound = rebound;
        }

        /**
         * N-201: the map an if arm or a loop body starts from (the TS
         * {@code ValueMap.nestedScope}) — every binding visible at the
         * if/loop, and nothing the nested scope binds flows back out.
         * {@code hidden} is a loop's iteration variable, never resolved
         * through an outer binding.
         */
        ValueMap nestedScope(String hidden) {
            ValueMap scope = new ValueMap(rebound);
            scope.putAll(this);
            if (hidden != null) scope.remove(hidden);
            return scope;
        }
    }

    /**
     * F-269: every name bound more than once in the method — binding names at
     * any depth (if/loop arms included) and loop iteration variables (the TS
     * {@code collectReboundNames}). {@link #canonical} never resolves through
     * one.
     */
    private static Set<String> collectReboundNames(AnfMethod method) {
        Set<String> seen = new HashSet<>();
        Set<String> rebound = new HashSet<>();
        collectReboundNames(orEmpty(method.body()), seen, rebound);
        return rebound;
    }

    private static void collectReboundNames(List<AnfBinding> bindings, Set<String> seen, Set<String> rebound) {
        for (AnfBinding b : bindings) {
            if (!seen.add(b.name())) rebound.add(b.name());
            AnfValue v = b.value();
            if (v instanceof If ifv) {
                collectReboundNames(orEmpty(ifv.thenBranch()), seen, rebound);
                collectReboundNames(orEmpty(ifv.elseBranch()), seen, rebound);
            }
            if (v instanceof Loop lp) {
                if (lp.iterVar() != null && !seen.add(lp.iterVar())) rebound.add(lp.iterVar());
                collectReboundNames(orEmpty(lp.body()), seen, rebound);
            }
        }
    }

    private static void collectBindingNames(List<AnfBinding> bindings, Set<String> used) {
        for (AnfBinding b : bindings) {
            used.add(b.name());
            AnfValue v = b.value();
            if (v instanceof LoadParam lp && lp.name() != null) used.add(lp.name());
            if (v instanceof LoadProp lp && lp.name() != null) used.add(lp.name());
            if (v instanceof If ifv) {
                collectBindingNames(orEmpty(ifv.thenBranch()), used);
                collectBindingNames(orEmpty(ifv.elseBranch()), used);
            }
            if (v instanceof Loop lp) {
                if (lp.iterVar() != null) used.add(lp.iterVar());
                collectBindingNames(orEmpty(lp.body()), used);
            }
        }
    }

    /**
     * Apply the 12 EC simplification rules. Returns the new value for the
     * binding's RHS or {@code null} if no rule fired.
     *
     * <p>Some rules need to introduce a fresh constant binding (e.g. when
     * combining two scalars into one). Those are appended to {@code prelude}
     * so the rewritten call can reference them.
     */
    /**
     * N-460 — what a fusing rule (R9, R10, R11) needs to know at its fire
     * site (the TS {@code FusionScope} in anf-ec.ts).
     *
     * <p>A fusion replaces the outer call with ONE new scalar multiplication,
     * so it shrinks the script only if {@link #removeGateSubsumedEcCalls}
     * then drops an inner call it read. Each fusing rule therefore fires only
     * when at least one of its inner operands is ELIMINABLE
     * ({@link #fusionEliminates}):
     * <ul>
     *   <li>every name on its alias chain (the operand, each {@code @ref:}
     *   hop, the call binding itself — {@link #canonical}'s walk) has exactly
     *   one referrer: the rewritten binding for the operand, the previous hop
     *   for the rest. Any other reader keeps the inner call alive after the
     *   fusion;</li>
     *   <li>the call is an {@code ecMulGen} bound in the current scope or an
     *   enclosing one inside the same loop body ({@code frame}). It needs no
     *   witness, but one bound outside a loop the fusion sits in would trade
     *   one multiplication for one per iteration;</li>
     *   <li>or the call is an {@code ecMul} bound in the current scope itself
     *   ({@code local}): the fused {@code ecMul} on the same point is then
     *   its witness. One bound in an enclosing scope has no witness (the
     *   fused call is nested) and stays.</li>
     * </ul>
     *
     * <p>{@code referrers} is computed once per sweep, from the body the
     * sweep starts with ({@link #countReferrers}), and not updated as the
     * sweep rewrites. A rewrite only adds a reference to a name its own
     * binding, or the inner binding it lifts from, already read, so a stale
     * count is never too low. Every tier computes it the same way, because
     * which rules fire decides the bytes.
     */
    private record FusionScope(Map<String, Integer> referrers, Set<String> local, Set<String> frame) {}

    /**
     * N-460: referrer count per name — the bindings, at any depth, whose
     * value reads it (once per binding, however many operands name it; an
     * {@code if} reads its {@code cond}, its arms' bindings are counted
     * themselves), plus one for each name in an {@code if}'s {@code results}
     * and one for a private method's return binding (F-108): the two things
     * {@link #removeGateSubsumedEcCalls} protects.
     */
    private static Map<String, Integer> countReferrers(List<AnfBinding> body, AnfMethod method) {
        Map<String, Integer> counts = new HashMap<>();
        countReferrers(body, counts);
        if (!"constructor".equals(method.name()) && !method.isPublic() && !body.isEmpty()) {
            counts.merge(body.get(body.size() - 1).name(), 1, Integer::sum);
        }
        return counts;
    }

    private static void countReferrers(List<AnfBinding> bindings, Map<String, Integer> counts) {
        for (AnfBinding b : bindings) {
            Set<String> reads = new HashSet<>();
            if (b.value() instanceof If ifv) {
                reads.add(ifv.cond());
                if (ifv.results() != null) reads.addAll(ifv.results());
            } else if (!(b.value() instanceof Loop)) {
                Dce.collectRefs(b.value(), reads);
            }
            for (String name : reads) counts.merge(name, 1, Integer::sum);
            if (b.value() instanceof If ifv) {
                countReferrers(orEmpty(ifv.thenBranch()), counts);
                countReferrers(orEmpty(ifv.elseBranch()), counts);
            } else if (b.value() instanceof Loop lp) {
                countReferrers(orEmpty(lp.body()), counts);
            }
        }
    }

    /** N-460: does fusing these inner operands let at least one inner call go? */
    private static boolean fusionEliminates(List<String> operands, Map<String, AnfValue> vm, FusionScope scope) {
        for (String operand : operands) {
            String c = canonical(operand, vm);
            if (c == null) continue;
            // canonical already walked this chain, so every hop is an @ref:.
            String cur = operand;
            boolean single = true;
            while (true) {
                if (scope.referrers().getOrDefault(cur, 0) != 1) {
                    single = false;
                    break;
                }
                if (cur.equals(c)) break;
                cur = ((BytesConst) ((LoadConst) vm.get(cur)).value()).hex().substring(5);
            }
            if (!single) continue;
            if (vm.get(c) instanceof Call call
                && (("ecMulGen".equals(call.func()) && scope.frame().contains(c))
                    || ("ecMul".equals(call.func()) && scope.local().contains(c)))) {
                return true;
            }
        }
        return false;
    }

    private static AnfValue tryOptimize(String name, AnfValue v, Map<String, AnfValue> vm, List<AnfBinding> prelude,
                                        Set<String> usedNames, FusionScope scope) {
        if (!(v instanceof Call call)) return null;
        String func = call.func();
        List<String> args = call.args();
        if (func == null || args == null) return null;

        // Rule 1: ecAdd(x, INFINITY) -> x, keeping ecAdd's operand gate (N-104)
        if ("ecAdd".equals(func) && args.size() == 2 && isInfinity(args.get(1), vm)) {
            emitOperandGate(false, name, args.get(0), vm, prelude, usedNames);
            return makeRef(args.get(0));
        }
        // Rule 2: ecAdd(INFINITY, x) -> x, keeping ecAdd's operand gate (N-104)
        if ("ecAdd".equals(func) && args.size() == 2 && isInfinity(args.get(0), vm)) {
            emitOperandGate(false, name, args.get(1), vm, prelude, usedNames);
            return makeRef(args.get(1));
        }
        // Rule 3: ecMul(x, 1) -> x, keeping ecMul's operand gate (N-104)
        if ("ecMul".equals(func) && args.size() == 2 && isConstInt(args.get(1), BigInteger.ONE, vm)) {
            emitOperandGate(true, name, args.get(0), vm, prelude, usedNames);
            return makeRef(args.get(0));
        }
        // Rule 4: ecMul(x, 0) -> INFINITY, keeping ecMul's operand gate (N-104)
        if ("ecMul".equals(func) && args.size() == 2 && isConstInt(args.get(1), BigInteger.ZERO, vm)) {
            emitOperandGate(true, name, args.get(0), vm, prelude, usedNames);
            return makeConstHex(INFINITY_HEX);
        }
        // Rule 5: ecMulGen(0) -> INFINITY
        if ("ecMulGen".equals(func) && args.size() == 1 && isConstInt(args.get(0), BigInteger.ZERO, vm)) {
            return makeConstHex(INFINITY_HEX);
        }
        // Rule 6: ecMulGen(1) -> G
        if ("ecMulGen".equals(func) && args.size() == 1 && isConstInt(args.get(0), BigInteger.ONE, vm)) {
            return makeConstHex(G_HEX);
        }
        // Rule 7: ecNegate(ecNegate(x)) -> x
        if ("ecNegate".equals(func) && args.size() == 1) {
            AnfValue inner = resolveValue(args.get(0), vm);
            // F-269 attempt 2: x is lifted out of the inner binding and
            // re-emitted here, so it must denote one value at both sites.
            if (inner instanceof Call ic && "ecNegate".equals(ic.func()) && ic.args() != null && ic.args().size() == 1
                    && stable(ic.args().get(0), vm)) {
                return makeRef(ic.args().get(0));
            }
        }
        // Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY, keeping the adder's y = 0 abort (N-251)
        if ("ecAdd".equals(func) && args.size() == 2) {
            AnfValue neg = resolveValue(args.get(1), vm);
            if (neg instanceof Call nc && "ecNegate".equals(nc.func()) && nc.args() != null && nc.args().size() == 1) {
                if (sameBinding(args.get(0), nc.args().get(0), vm)) {
                    emitNegCancelGate(name, args.get(0), vm, prelude, usedNames);
                    return makeConstHex(INFINITY_HEX);
                }
            }
        }
        // Rule 8r (`ec-add-negate-cancel-reversed`): ecAdd(ecNegate(x), x) -> INFINITY
        //
        // The mirror of Rule 8. It has always been in optimizer/ec-rules.json and
        // the Go tier -- whose rule engine executes that file directly --
        // performed it; the six hand-ported tiers implemented only the forward
        // direction, so the same ANF compiled to a 1808-byte script in Go and a
        // 26140-byte one everywhere else (R-034 / CL-BUG-028).
        //
        // Placed after Rule 8 and before Rules 9/10/11 to match the JSON's rule
        // order, which is the order the Go engine tries them in.
        if ("ecAdd".equals(func) && args.size() == 2) {
            AnfValue neg = resolveValue(args.get(0), vm);
            if (neg instanceof Call nc && "ecNegate".equals(nc.func()) && nc.args() != null && nc.args().size() == 1) {
                if (sameBinding(args.get(1), nc.args().get(0), vm)) {
                    // The gate reads the ecNegate operand: the name the JSON's
                    // `$x` binds first, as the Go engine binds it (differs from
                    // args[1] only through an alias, F-269).
                    emitNegCancelGate(name, nc.args().get(0), vm, prelude, usedNames);
                    return makeConstHex(INFINITY_HEX);
                }
            }
        }
        // Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2 mod N)
        if ("ecMul".equals(func) && args.size() == 2) {
            AnfValue inner = resolveValue(args.get(0), vm);
            BigInteger k2 = getConstInt(args.get(1), vm);
            if (inner instanceof Call ic && "ecMul".equals(ic.func())
                    && ic.args() != null && ic.args().size() == 2 && k2 != null
                    && stable(ic.args().get(0), vm)) {
                BigInteger k1 = getConstInt(ic.args().get(1), vm);
                if (k1 != null && fusionEliminates(List.of(args.get(0)), vm, scope)) {
                    BigInteger combined = k1.multiply(k2).mod(CURVE_N);
                    String fresh = freshConstName(name, combined, vm, prelude, usedNames);
                    return new Call("ecMul", List.of(ic.args().get(0), fresh));
                }
            }
        }
        // Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen((k1+k2) mod N)
        if ("ecAdd".equals(func) && args.size() == 2) {
            AnfValue left = resolveValue(args.get(0), vm);
            AnfValue right = resolveValue(args.get(1), vm);
            if (left instanceof Call lc && "ecMulGen".equals(lc.func()) && lc.args() != null && lc.args().size() == 1
                    && right instanceof Call rc && "ecMulGen".equals(rc.func()) && rc.args() != null && rc.args().size() == 1) {
                BigInteger k1 = getConstInt(lc.args().get(0), vm);
                BigInteger k2 = getConstInt(rc.args().get(0), vm);
                if (k1 != null && k2 != null && fusionEliminates(args, vm, scope)) {
                    BigInteger combined = k1.add(k2).mod(CURVE_N);
                    String fresh = freshConstName(name, combined, vm, prelude, usedNames);
                    return new Call("ecMulGen", List.of(fresh));
                }
            }
        }
        // Rule 11: ecAdd(ecMul(k1,p), ecMul(k2,p)) -> ecMul(p, k1+k2 mod N)
        if ("ecAdd".equals(func) && args.size() == 2) {
            AnfValue left = resolveValue(args.get(0), vm);
            AnfValue right = resolveValue(args.get(1), vm);
            if (left instanceof Call lc && "ecMul".equals(lc.func()) && lc.args() != null && lc.args().size() == 2
                    && right instanceof Call rc && "ecMul".equals(rc.func()) && rc.args() != null && rc.args().size() == 2
                    && sameBinding(lc.args().get(0), rc.args().get(0), vm)) {
                BigInteger k1 = getConstInt(lc.args().get(1), vm);
                BigInteger k2 = getConstInt(rc.args().get(1), vm);
                if (k1 != null && k2 != null && fusionEliminates(args, vm, scope)) {
                    BigInteger combined = k1.add(k2).mod(CURVE_N);
                    String fresh = freshConstName(name, combined, vm, prelude, usedNames);
                    return new Call("ecMul", List.of(lc.args().get(0), fresh));
                }
            }
        }
        // Rule 12: ecMul(G, k) -> ecMulGen(k)
        if ("ecMul".equals(func) && args.size() == 2 && isGenerator(args.get(0), vm)) {
            return new Call("ecMulGen", List.of(args.get(1)));
        }
        return null;
    }

    // ---------- value-inspection helpers (port of Python helpers) ----------

    /**
     * Resolve a binding name to its current ANFValue, following {@code @ref:}
     * aliases (F-269, {@link #canonical}).
     */
    private static AnfValue resolveValue(String name, Map<String, AnfValue> vm) {
        String c = canonical(name, vm);
        return c == null ? null : vm.get(c);
    }

    /**
     * F-269 attempt 2: may a name lifted out of an earlier binding be emitted
     * at the current site? Only when it denotes one value (R7, R9).
     */
    private static boolean stable(String name, Map<String, AnfValue> vm) {
        return canonical(name, vm) != null;
    }

    /**
     * F-269 (user decision R77): the binding {@code name} ultimately names,
     * following {@code load_const "@ref:<x>"} aliases — pass 04's
     * {@code const y = <expr>} and the ones R1/R2/R3/R7 leave behind (the TS
     * {@code canonicalName} in anf-ec.ts). It used to be the identity: the
     * port copied Python's alias chase, which looked for the alias on a
     * {@code load_param} value no tier emits.
     *
     * <p>{@code null} when {@code name} has no position-independent
     * identity: ANF re-emits a local's name when the source reassigns it (top
     * level or in an if/loop arm), so a REBOUND name means different values
     * at different sites. Two uses of one are not "the same $x", and nothing
     * lifted out of an earlier binding may name one (F-269 attempt 2). An
     * alias cycle (only hand-written {@code --ir}) is {@code null} too. A hop
     * is never taken INTO a rebound name: the chain stops at the last name
     * bound once, which is itself a fixed value, and its value is the opaque
     * alias. Matching only — rewrites emit the literal names they matched.
     */
    private static String canonical(String name, Map<String, AnfValue> vm) {
        Set<String> rebound = vm instanceof ValueMap m ? m.rebound : Set.of();
        if (rebound.contains(name)) return null;
        Set<String> seen = new HashSet<>();
        seen.add(name);
        String cur = name;
        while (true) {
            AnfValue v = vm.get(cur);
            if (!(v instanceof LoadConst lc) || !(lc.value() instanceof BytesConst bs)) return cur;
            String s = bs.hex();
            if (s == null || s.length() <= 5 || !s.startsWith("@ref:")) return cur;
            String next = s.substring(5);
            if (rebound.contains(next)) return cur;
            if (!seen.add(next)) return null;
            cur = next;
        }
    }

    private static boolean sameBinding(String a, String b, Map<String, AnfValue> vm) {
        String ca = canonical(a, vm);
        return ca != null && ca.equals(canonical(b, vm));
    }

    private static boolean isInfinity(String name, Map<String, AnfValue> vm) {
        AnfValue val = resolveValue(name, vm);
        return val instanceof LoadConst lc && lc.value() instanceof BytesConst bs
            && INFINITY_HEX.equals(bs.hex());
    }

    private static boolean isGenerator(String name, Map<String, AnfValue> vm) {
        AnfValue val = resolveValue(name, vm);
        return val instanceof LoadConst lc && lc.value() instanceof BytesConst bs
            && G_HEX.equals(bs.hex());
    }

    private static boolean isConstInt(String name, BigInteger n, Map<String, AnfValue> vm) {
        AnfValue val = resolveValue(name, vm);
        if (val instanceof LoadConst lc && lc.value() instanceof BigIntConst bc) {
            return n.equals(bc.value());
        }
        return false;
    }

    private static BigInteger getConstInt(String name, Map<String, AnfValue> vm) {
        AnfValue val = resolveValue(name, vm);
        if (val instanceof LoadConst lc && lc.value() instanceof BigIntConst bc) {
            return bc.value();
        }
        return null;
    }

    // ---------- value-construction helpers ----------

    private static AnfValue makeRef(String name) {
        return new LoadConst(new BytesConst("@ref:" + name));
    }

    private static AnfValue makeConstHex(String hex) {
        return new LoadConst(new BytesConst(hex));
    }

    /** secp256k1 field prime. */
    private static final BigInteger FIELD_P = new BigInteger(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);

    /**
     * N-104 — the operand gate a rewrite must leave behind. Byte-for-byte the
     * TS reference ({@code emitAddOperandGate} / {@code emitMulOperandGate} in
     * packages/runar-compiler/src/optimizer/anf-ec.ts) and the "gate" entries
     * in optimizer/ec-rules.json:
     *
     * <pre>
     *   ecAdd: assert(ecPointX(q) &lt; p &amp;&amp; ecPointY(q) &lt; p)   width (CL-BUG-095) + canonicity (R-117)
     *   ecMul: assert(q === O || ecOnCurve(q))               on-curve-or-O (R-157)
     * </pre>
     *
     * <p>R1-R4 replace a builtin whose first act is to validate q; without
     * this a malformed or off-curve q was accepted by the default compile and
     * aborted under disableEcOptimizer. Built only from forms no rule matches,
     * so the fixed-point loop cannot rewrite it on a later pass. Names follow
     * the TS {@code freshName}: {@code <base><suffix>}, else the first unused
     * {@code ..._<i>}.
     */
    private static void emitOperandGate(boolean ofMul, String base, String q, Map<String, AnfValue> vm,
                                        List<AnfBinding> prelude, Set<String> usedNames) {
        java.util.function.BiFunction<String, AnfValue, String> add = (suffix, value) -> {
            String n = base + suffix;
            for (int i = 1; usedNames.contains(n); i++) n = base + suffix + "_" + i;
            usedNames.add(n);
            vm.put(n, value);
            prelude.add(new AnfBinding(n, value, null));
            return n;
        };
        String ok;
        if (ofMul) {
            String inf = add.apply("_inf", makeConstHex(INFINITY_HEX));
            String isInf = add.apply("_isinf", new BinOp("===", q, inf, "bytes"));
            String onCurve = add.apply("_oncurve", new Call("ecOnCurve", List.of(q)));
            ok = add.apply("_ok", new BinOp("||", isInf, onCurve, null));
        } else {
            String px = add.apply("_px", new Call("ecPointX", List.of(q)));
            String py = add.apply("_py", new Call("ecPointY", List.of(q)));
            String fp = add.apply("_fp", new LoadConst(new BigIntConst(FIELD_P)));
            String xOk = add.apply("_pxok", new BinOp("<", px, fp, null));
            String yOk = add.apply("_pyok", new BinOp("<", py, fp, null));
            ok = add.apply("_ok", new BinOp("&&", xOk, yOk, null));
        }
        add.apply("_gate", new Assert(ok));
    }

    /**
     * N-251 — the gate R8/R8r ({@code ecAdd(q, ecNegate(q)) -> O} and its
     * mirror) must leave behind (user decision R96). Byte-for-byte the TS
     * reference ({@code emitNegCancelGate} in
     * packages/runar-compiler/src/optimizer/anf-ec.ts):
     *
     * <pre>
     *   assert(ecPointX(q) === 0 || ecPointY(q) !== 0)
     * </pre>
     *
     * <p>The replaced ecAdd doubles exactly when y(q) = 0, and N-110 made the
     * adder abort on a doubling with px != 0 and py == 0; the px == 0 term
     * keeps O + O = O. Width and canonicity are checked by the inner
     * ecNegate(q) call, which is never dead-code-eliminated. Names as in
     * {@link #emitOperandGate}.
     */
    private static void emitNegCancelGate(String base, String q, Map<String, AnfValue> vm,
                                          List<AnfBinding> prelude, Set<String> usedNames) {
        java.util.function.BiFunction<String, AnfValue, String> add = (suffix, value) -> {
            String n = base + suffix;
            for (int i = 1; usedNames.contains(n); i++) n = base + suffix + "_" + i;
            usedNames.add(n);
            vm.put(n, value);
            prelude.add(new AnfBinding(n, value, null));
            return n;
        };
        String px = add.apply("_px", new Call("ecPointX", List.of(q)));
        String py = add.apply("_py", new Call("ecPointY", List.of(q)));
        String zero = add.apply("_zero", new LoadConst(new BigIntConst(BigInteger.ZERO)));
        String xZero = add.apply("_pxz", new BinOp("===", px, zero, null));
        String yNonZero = add.apply("_pynz", new BinOp("!==", py, zero, null));
        String ok = add.apply("_ok", new BinOp("||", xZero, yNonZero, null));
        add.apply("_gate", new Assert(ok));
    }

    /**
     * Bind the fused scalar {@code value} under a fresh name and append it to
     * {@code prelude} so the rewritten call can reference it. Returns the name.
     *
     * <p>F-185: the name is the TS {@code freshName(`${binding.name}_k`,
     * usedNames)} of packages/runar-compiler/src/optimizer/anf-ec.ts —
     * {@code <binding>_k}, else the first unused {@code <binding>_k_<i>}. It
     * used to come from a JVM-global counter ({@code __ec_opt_N}) that was
     * never reset, so identical {@code --daemon} requests emitted different
     * ANF. The name now depends only on the method being optimised.
     *
     * <p>F-086: the name skips every name the method already uses
     * ({@code usedNames}, see {@link #collectUsedNames}) and is reserved there.
     */
    private static String freshConstName(String bindingName, BigInteger value, Map<String, AnfValue> vm,
                                         List<AnfBinding> prelude, Set<String> usedNames) {
        String base = bindingName + "_k";
        String name = base;
        for (int i = 1; usedNames.contains(name); i++) name = base + "_" + i;
        usedNames.add(name);
        AnfValue v = new LoadConst(new BigIntConst(value));
        vm.put(name, v);
        prelude.add(new AnfBinding(name, v, null));
        return name;
    }

    // R-261: ~250 lines of a SECOND optimizer used to sit here —
    // `runFullOptimizer` -> `optimizeMethod` -> `collapseTautologicalIfs`, all
    // private, all referenced only by each other, and marked
    // @SuppressWarnings("unused") to keep the compiler quiet about it. The live
    // entry point is `run` above, which goes through `optimizeEcMethod`.
    //
    // It is deleted rather than commented, because of what earlier work already
    // had to do to it: `collapseTautologicalIfs` carried a rule that hoisted a
    // then-arm's bindings — property writes included — out of any `if` whose
    // else arm was empty, which is EVERY `if` without an else. That rule was
    // removed with a note saying it "had to go before someone re-enables the
    // optimiser". Keeping the rest of an unreachable optimizer in the
    // production pass file is the same hazard one step back.



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
                renameInBody(orEmpty(ifv.elseBranch()), rename),
                ifv.results());
        }
        if (v instanceof Loop lp) {
            return new Loop(lp.count(), renameInBody(orEmpty(lp.body()), rename), lp.iterVar(), lp.start(), lp.step());
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
        if (v instanceof RawScript) {
            // Opaque byte span — no SSA operand refs to rename.
            return v;
        }
        // Exhaustiveness guard. Silently returning the value would drop a
        // pending rename and corrupt downstream lowering.
        throw new UnknownAnfKindError(v.kind(), "anf-optimize.renameInValue");
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
    //
    // The DCE pass lives in its own discrete module now (passes/Dce.java).
    // Delegate to it so the EC rewrite's post-cleanup uses the canonical
    // implementation.

    private static List<AnfBinding> eliminateDead(AnfMethod method) {
        return Dce.eliminateDead(method);
    }

    private static <T> List<T> orEmpty(List<T> list) {
        return list == null ? List.of() : list;
    }
}
