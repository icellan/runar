package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import runar.compiler.ir.anf.AddDataOutput;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AddRawOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.DeserializeState;
import runar.compiler.ir.anf.GetStateScript;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.UpdateProp;

/**
 * N-101: the scaffolding StatefulSmartContract lowering injects, re-derived for
 * {@code --ir} input.
 *
 * <p>{@code --ir} skips the frontend, so a program labelled (or, per N-087,
 * inferred) StatefulSmartContract could omit or fake the scaffolding ANF
 * lowering injects into every public method and compile to an anyone-can-spend
 * script: F-107's attack body compiled to {@code 76767b8777}. For each public
 * method this re-derives what the frontend would inject (the TypeScript
 * reference is packages/runar-compiler/src/passes/stateful-scaffold.ts):
 * the prologue ({@code assert(checkPreimage(txPreimage))}, the sighash-type
 * assert and, when the contract has mutable properties, deserialize_state),
 * free user code, then, when the method mutates state or declares outputs,
 * the continuation (the {@code _newAmount} floor in the single-output form,
 * the change output and the hashOutputs comparison over every output in
 * order). It refuses the program, with the diagnostics all seven tiers share
 * (conformance/negatives/ir-stateful-scaffold-cases.json), when (1) the
 * auto-injected parameters, (2) the prologue or (3) the continuation differ,
 * or (4) a scaffolding binding, or an output the continuation commits to, is
 * bound more than once or shares a property or parameter name.
 */
final class StatefulScaffold {

    private static final int SIGHASH_DEFAULT = 0x41;

    private StatefulScaffold() {}

    private static final class Emitter {
        final Set<String> taken;
        final int[] counter;
        final List<AnfBinding> out = new ArrayList<>();

        Emitter(Set<String> taken, int[] counter) {
            this.taken = taken;
            this.counter = counter;
        }

        String emit(AnfValue v) {
            String name;
            do {
                name = "$scaffold" + counter[0]++;
            } while (taken.contains(name));
            out.add(new AnfBinding(name, v, null));
            return name;
        }

        Emitter sub() {
            return new Emitter(taken, counter);
        }
    }

    private static void prologue(Emitter e, int sighashMode, boolean hasMutableState) {
        String pre = e.emit(new LoadParam("txPreimage"));
        String check = e.emit(new CheckPreimage(pre, sighashMode == SIGHASH_DEFAULT ? null : sighashMode));
        e.emit(new Assert(check));
        String p2 = e.emit(new LoadParam("txPreimage"));
        String typ = e.emit(new Call("extractSigHashType", List.of(p2)));
        String want = e.emit(new LoadConst(new BigIntConst(BigInteger.valueOf(sighashMode))));
        e.emit(new Assert(e.emit(new BinOp("===", typ, want, null))));
        if (hasMutableState) {
            String p3 = e.emit(new LoadParam("txPreimage"));
            e.emit(new DeserializeState(p3));
        }
    }

    private static void continuation(Emitter e, boolean needsChange, List<String> stateRefs, List<String> dataRefs) {
        if (!needsChange) return;
        if (stateRefs.isEmpty()) {
            String p = e.emit(new LoadParam("txPreimage"));
            String amount = e.emit(new Call("extractAmount", List.of(p)));
            String na = e.emit(new LoadParam("_newAmount"));
            e.emit(new Assert(e.emit(new BinOp(">=", na, amount, null))));
        }
        String pkh = e.emit(new LoadParam("_changePKH"));
        String amt = e.emit(new LoadParam("_changeAmount"));
        String zero = e.emit(new LoadConst(new BigIntConst(BigInteger.ZERO)));
        String nonZero = e.emit(new BinOp("!==", amt, zero, null));
        Emitter thenE = e.sub();
        thenE.emit(new Call("buildChangeOutput", List.of(pkh, amt)));
        Emitter elseE = e.sub();
        elseE.emit(new LoadConst(new BytesConst("")));
        String change = e.emit(new If(nonZero, thenE.out, elseE.out));
        String acc;
        if (!stateRefs.isEmpty()) {
            acc = stateRefs.get(0);
            for (String r : stateRefs.subList(1, stateRefs.size())) acc = e.emit(new Call("cat", List.of(acc, r)));
        } else {
            String script = e.emit(new GetStateScript());
            String p = e.emit(new LoadParam("txPreimage"));
            String na = e.emit(new LoadParam("_newAmount"));
            acc = e.emit(new Call("computeStateOutput", List.of(p, script, na)));
        }
        for (String r : dataRefs) acc = e.emit(new Call("cat", List.of(acc, r)));
        acc = e.emit(new Call("cat", List.of(acc, change)));
        String hash = e.emit(new Call("hash256", List.of(acc)));
        String p = e.emit(new LoadParam("txPreimage"));
        String outHash = e.emit(new Call("extractOutputHash", List.of(p)));
        String eq = e.emit(new BinOp("===", hash, outHash, "bytes"));
        e.emit(new Assert(eq, true));
    }

    private static List<List<AnfBinding>> nested(AnfValue v) {
        List<List<AnfBinding>> out = new ArrayList<>();
        if (v instanceof If iff) {
            if (iff.thenBranch() != null) out.add(iff.thenBranch());
            if (iff.elseBranch() != null) out.add(iff.elseBranch());
        } else if (v instanceof Loop loop && loop.body() != null) {
            out.add(loop.body());
        }
        return out;
    }

    private static boolean isStateOutput(AnfValue v) {
        return v instanceof AddOutput || v instanceof AddRawOutput;
    }

    private static boolean contains(List<AnfBinding> bindings, boolean state) {
        for (AnfBinding b : bindings) {
            if (state ? isStateOutput(b.value()) : b.value() instanceof AddDataOutput) return true;
            for (List<AnfBinding> n : nested(b.value())) if (contains(n, state)) return true;
        }
        return false;
    }

    /**
     * The frontend's side-effect summary, read off the IR (update_prop is a
     * state mutation, add_output / add_raw_output a state output,
     * add_data_output a data output) at any depth and through method_calls to
     * private methods. Returns {needsChange, needsNewAmount}.
     */
    private static boolean[] shape(List<AnfMethod> methods, AnfMethod method) {
        Map<String, AnfMethod> privates = new HashMap<>();
        for (AnfMethod m : methods) {
            if (!m.isPublic() && !"constructor".equals(m.name())) privates.put(m.name(), m);
        }
        boolean[] fx = new boolean[3];
        Set<String> visited = new HashSet<>();
        walkEffects(method.body(), privates, visited, fx);
        boolean mutates = fx[0], state = fx[1], data = fx[2];
        return new boolean[] {mutates || state || data, (mutates || data) && !state};
    }

    private static void walkEffects(List<AnfBinding> bindings, Map<String, AnfMethod> privates, Set<String> visited, boolean[] fx) {
        for (AnfBinding b : bindings) {
            AnfValue v = b.value();
            if (v instanceof UpdateProp) fx[0] = true;
            else if (isStateOutput(v)) fx[1] = true;
            else if (v instanceof AddDataOutput) fx[2] = true;
            else if (v instanceof MethodCall mc) {
                AnfMethod target = privates.get(mc.method());
                if (target != null && visited.add(target.name())) walkEffects(target.body(), privates, visited, fx);
            }
            for (List<AnfBinding> n : nested(v)) walkEffects(n, privates, visited, fx);
        }
    }

    private static String describe(AnfValue v) {
        if (v instanceof LoadParam lp) return "load_param " + lp.name();
        if (v instanceof LoadConst lc) {
            if (lc.value() instanceof BytesConst bc) return "load_const \"" + bc.hex() + "\"";
            if (lc.value() instanceof BigIntConst bi) return "load_const " + bi.value();
        }
        if (v instanceof Call c) return "call " + c.func();
        if (v instanceof BinOp op) return "bin_op " + op.op();
        return v.kind();
    }

    private static String normType(String t) {
        return t == null || t.isEmpty() ? null : t;
    }

    private static final class Matcher {
        final Map<String, String> map = new HashMap<>();
        final Set<String> mapped = new HashSet<>();

        boolean ref(String e, String a) {
            return map.containsKey(e) ? Objects.equals(map.get(e), a) : Objects.equals(e, a);
        }

        boolean binding(AnfBinding exp, AnfBinding act) {
            AnfValue e = exp.value();
            AnfValue a = act.value();
            boolean ok;
            if (e instanceof LoadParam el && a instanceof LoadParam al) {
                ok = el.name().equals(al.name());
            } else if (e instanceof LoadConst ec && a instanceof LoadConst ac) {
                if (ec.value() instanceof BigIntConst eb) {
                    ok = ac.value() instanceof BigIntConst ab && eb.value().equals(ab.value());
                } else {
                    ok = ac.value() instanceof BytesConst ab && ((BytesConst) ec.value()).hex().equals(ab.hex());
                }
            } else if (e instanceof CheckPreimage ec && a instanceof CheckPreimage ac) {
                int ef = ec.sighashFlag() == null || ec.sighashFlag() == 0 ? SIGHASH_DEFAULT : ec.sighashFlag();
                int af = ac.sighashFlag() == null || ac.sighashFlag() == 0 ? SIGHASH_DEFAULT : ac.sighashFlag();
                ok = ref(ec.preimage(), ac.preimage()) && ef == af;
            } else if (e instanceof Assert ea && a instanceof Assert aa) {
                ok = ref(ea.value(), aa.value());
            } else if (e instanceof Call ec && a instanceof Call ac) {
                List<String> aargs = ac.args() == null ? List.of() : ac.args();
                ok = ec.func().equals(ac.func()) && ec.args().size() == aargs.size();
                for (int i = 0; ok && i < aargs.size(); i++) ok = ref(ec.args().get(i), aargs.get(i));
            } else if (e instanceof BinOp eb && a instanceof BinOp ab) {
                ok = eb.op().equals(ab.op()) && ref(eb.left(), ab.left()) && ref(eb.right(), ab.right())
                    && Objects.equals(normType(eb.resultType()), normType(ab.resultType()));
            } else if (e instanceof DeserializeState ed && a instanceof DeserializeState ad) {
                ok = ref(ed.preimage(), ad.preimage());
            } else if (e instanceof GetStateScript && a instanceof GetStateScript) {
                ok = true;
            } else if (e instanceof If ei && a instanceof If ai) {
                List<AnfBinding> at = ai.thenBranch() == null ? List.of() : ai.thenBranch();
                List<AnfBinding> ae = ai.elseBranch() == null ? List.of() : ai.elseBranch();
                ok = ref(ei.cond(), ai.cond()) && (ai.results() == null || ai.results().isEmpty())
                    && sequence(ei.thenBranch(), at) == -1 && sequence(ei.elseBranch(), ae) == -1;
            } else {
                ok = false;
            }
            if (!ok || mapped.contains(act.name())) return false;
            map.put(exp.name(), act.name());
            mapped.add(act.name());
            return true;
        }

        /** Index of the first binding that differs (a missing one included), or -1. */
        int sequence(List<AnfBinding> exp, List<AnfBinding> act) {
            for (int i = 0; i < exp.size(); i++) {
                if (i >= act.size() || !binding(exp.get(i), act.get(i))) return i;
            }
            return act.size() == exp.size() ? -1 : exp.size();
        }
    }

    private static void collectNames(List<AnfBinding> bindings, Map<String, Integer> counts) {
        for (AnfBinding b : bindings) {
            counts.merge(b.name(), 1, Integer::sum);
            if (b.value() instanceof If iff && iff.results() != null) {
                for (String r : iff.results()) counts.merge(r, 1, Integer::sum);
            }
            if (b.value() instanceof Loop loop && loop.iterVar() != null && !loop.iterVar().isEmpty()) {
                counts.merge(loop.iterVar(), 1, Integer::sum);
            }
            for (List<AnfBinding> n : nested(b.value())) collectNames(n, counts);
        }
    }

    private static RuntimeException scaffold(String method, String detail) {
        return new RuntimeException("IR validation: stateful method '" + method
            + "' does not carry the scaffolding StatefulSmartContract lowering injects: " + detail);
    }

    private static void preorder(List<AnfBinding> bindings, List<AnfBinding> out) {
        for (AnfBinding b : bindings) {
            out.add(b);
            for (List<AnfBinding> n : nested(b.value())) preorder(n, out);
        }
    }

    static void check(List<AnfProperty> props, List<AnfMethod> methods) {
        boolean hasMutable = props.stream().anyMatch(p -> !p.readonly());
        Set<String> propNames = new HashSet<>();
        for (AnfProperty p : props) propNames.add(p.name());

        for (AnfMethod m : methods) {
            if (!m.isPublic() || "constructor".equals(m.name())) continue;
            boolean[] shape = shape(methods, m);
            boolean needsChange = shape[0];
            boolean needsNewAmount = shape[1];

            // (1) the parameters, contiguous and once each.
            List<String[]> required = new ArrayList<>();
            if (needsChange) {
                required.add(new String[] {"_changePKH", "Ripemd160"});
                required.add(new String[] {"_changeAmount", "bigint"});
            }
            if (needsNewAmount) required.add(new String[] {"_newAmount", "bigint"});
            required.add(new String[] {"txPreimage", "SigHashPreimage"});
            List<AnfParam> params = m.params();
            int start = -1;
            for (int i = 0; i < params.size(); i++) {
                if (params.get(i).name().equals(required.get(0)[0])) {
                    start = i;
                    break;
                }
            }
            boolean paramsOk = start >= 0;
            for (int i = 0; paramsOk && i < required.size(); i++) {
                String[] r = required.get(i);
                int count = 0;
                for (AnfParam p : params) if (p.name().equals(r[0])) count++;
                paramsOk = start + i < params.size() && params.get(start + i).name().equals(r[0])
                    && r[1].equals(params.get(start + i).type()) && count == 1;
            }
            if (!paramsOk) {
                List<String> listed = new ArrayList<>();
                for (String[] r : required) listed.add(r[0] + ": " + r[1]);
                throw new RuntimeException("IR validation: stateful method '" + m.name()
                    + "' must declare the auto-injected parameters (" + String.join(", ", listed)
                    + ") contiguously and once each, as StatefulSmartContract lowering does");
            }

            Map<String, Integer> counts = new HashMap<>();
            collectNames(m.body(), counts);
            int[] counter = {0};
            Matcher match = new Matcher();

            // (2) the prologue.
            Emitter pro = new Emitter(counts.keySet(), counter);
            prologue(pro, m.sighashType() == null ? SIGHASH_DEFAULT : m.sighashType(), hasMutable);
            List<AnfBinding> body = m.body();
            List<AnfBinding> head = body.subList(0, Math.min(pro.out.size(), body.size()));
            int pi = match.sequence(pro.out, head);
            if (pi != -1) throw scaffold(m.name(), "prologue binding " + pi + " must be " + describe(pro.out.get(pi).value()));

            // (3) the continuation, over the outputs the method's own top-level
            // bindings declare (an `if` counts once, as a state output when
            // either arm holds one, else as a data output), in order.
            List<AnfBinding> rest = body.subList(pro.out.size(), body.size());
            List<AnfBinding> stateOut = new ArrayList<>();
            List<AnfBinding> dataOut = new ArrayList<>();
            for (AnfBinding b : rest) {
                AnfValue v = b.value();
                if (isStateOutput(v)) {
                    stateOut.add(b);
                } else if (v instanceof AddDataOutput) {
                    dataOut.add(b);
                } else if (v instanceof If) {
                    if (nested(v).stream().anyMatch(n -> contains(n, true))) stateOut.add(b);
                    else if (nested(v).stream().anyMatch(n -> contains(n, false))) dataOut.add(b);
                }
            }
            List<String> stateRefs = new ArrayList<>();
            for (AnfBinding b : stateOut) stateRefs.add(b.name());
            List<String> dataRefs = new ArrayList<>();
            for (AnfBinding b : dataOut) dataRefs.add(b.name());
            Emitter tail = new Emitter(counts.keySet(), counter);
            continuation(tail, needsChange, stateRefs, dataRefs);
            int offset = rest.size() - tail.out.size();
            for (int i = 0; i < tail.out.size(); i++) {
                if (offset + i < 0 || !match.binding(tail.out.get(i), rest.get(offset + i))) {
                    throw scaffold(m.name(), "continuation binding " + i + " must be " + describe(tail.out.get(i).value()));
                }
            }

            // (4) unique, unshadowed names for what the scaffolding binds or
            // commits to. A binding's own arms may reuse its name (an
            // output-carrying `if` is named after its arm's last binding).
            Set<String> paramNames = new HashSet<>();
            for (AnfParam p : params) paramNames.add(p.name());
            List<AnfBinding> checked = new ArrayList<>();
            preorder(head, checked);
            if (offset >= 0) preorder(rest.subList(offset, rest.size()), checked);
            checked.addAll(stateOut);
            checked.addAll(dataOut);
            for (AnfBinding b : checked) {
                Map<String, Integer> inner = new HashMap<>();
                for (List<AnfBinding> n : nested(b.value())) collectNames(n, inner);
                int outside = counts.getOrDefault(b.name(), 0) - inner.getOrDefault(b.name(), 0);
                if (outside != 1 || propNames.contains(b.name()) || paramNames.contains(b.name())) {
                    throw new RuntimeException("IR validation: stateful method '" + m.name() + "' must bind '"
                        + b.name() + "' exactly once, under a name no property or parameter uses: the injected"
                        + " scaffolding binds it or the continuation commits to it");
                }
            }
        }
    }
}
