package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.UpdateProp;

/**
 * N-205 (b) — F-286's verifyRabinSig key-provenance rule, and N-205 (a)'s rule
 * for writes to a key property, re-asserted on {@code --ir} input. Port of
 * {@code packages/runar-compiler/src/ir/rabin-key-provenance.ts}: same rule,
 * same refusal order, same words. See that file's header for the spec.
 *
 * <p>Refusals:
 * <pre>
 *   IR validation: method '&lt;m&gt;': &lt;F-286 message&gt;
 *   IR validation: method '&lt;m&gt;': &lt;N-205 key-write message&gt;
 * </pre>
 */
public final class RabinKeyProvenance {

    private RabinKeyProvenance() {}

    private record Site(List<String> args, AnfMethod method) {}

    private record Write(String prop, String value, AnfMethod method) {}

    private static void flatten(List<AnfBinding> bindings, List<AnfBinding> out) {
        if (bindings == null) return;
        for (AnfBinding b : bindings) {
            out.add(b);
            AnfValue v = b.value();
            if (v instanceof If iff) {
                flatten(iff.thenBranch(), out);
                flatten(iff.elseBranch(), out);
            } else if (v instanceof Loop loop) {
                flatten(loop.body(), out);
            }
        }
    }

    private static boolean isPrivate(AnfMethod m) {
        return !m.isPublic() && !"constructor".equals(m.name());
    }

    private static int paramIndex(AnfMethod m, String name) {
        for (int i = 0; i < m.params().size(); i++) {
            if (m.params().get(i).name().equals(name)) return i;
        }
        return -1;
    }

    private static String refOf(AnfValue v) {
        if (v instanceof LoadConst lc && lc.value() instanceof BytesConst bc
            && bc.hex() != null && bc.hex().startsWith("@ref:")) {
            return bc.hex().substring(5);
        }
        return null;
    }

    private final Map<AnfMethod, List<AnfBinding>> flat = new LinkedHashMap<>();
    private final Map<AnfMethod, Map<String, List<AnfValue>>> byName = new HashMap<>();
    private final Map<String, AnfMethod> privates = new LinkedHashMap<>();
    private final Map<String, List<Site>> callSites = new HashMap<>();
    private final Map<String, Set<Integer>> trustedParams = new HashMap<>();

    public static void check(List<AnfProperty> props, List<AnfMethod> methods) {
        new RabinKeyProvenance().run(props, methods);
    }

    private void run(List<AnfProperty> props, List<AnfMethod> methods) {
        for (AnfMethod m : methods) {
            List<AnfBinding> list = new ArrayList<>();
            flatten(m.body(), list);
            flat.put(m, list);
            Map<String, List<AnfValue>> names = new HashMap<>();
            for (AnfBinding b : list) names.computeIfAbsent(b.name(), k -> new ArrayList<>()).add(b.value());
            byName.put(m, names);
        }
        for (AnfMethod m : methods) {
            if (isPrivate(m)) {
                privates.put(m.name(), m);
                callSites.put(m.name(), new ArrayList<>());
                trustedParams.put(m.name(), new HashSet<>());
            }
        }
        for (AnfMethod m : methods) {
            for (AnfBinding b : flat.get(m)) {
                if (b.value() instanceof MethodCall mc && privates.containsKey(mc.method())) {
                    callSites.get(mc.method()).add(new Site(mc.args(), m));
                }
            }
        }

        boolean changed = true;
        while (changed) {
            changed = false;
            for (Map.Entry<String, AnfMethod> e : privates.entrySet()) {
                List<Site> sites = callSites.get(e.getKey());
                if (sites.isEmpty()) continue;
                Set<Integer> trusted = trustedParams.get(e.getKey());
                for (int i = 0; i < e.getValue().params().size(); i++) {
                    if (trusted.contains(i)) continue;
                    final int idx = i;
                    boolean all = sites.stream().allMatch(s ->
                        idx < s.args().size() && isTrusted(s.args().get(idx), s.method(), new HashSet<>()));
                    if (all) {
                        trusted.add(i);
                        changed = true;
                    }
                }
            }
        }

        Set<String> keyProps = new HashSet<>();
        for (AnfMethod m : methods) {
            for (AnfBinding b : flat.get(m)) {
                if (b.value() instanceof Call c && "verifyRabinSig".equals(c.func()) && c.args().size() >= 4) {
                    sourcesOf(c.args().get(3), m, keyProps, new HashSet<>());
                }
            }
        }

        List<String> mutableProps = new ArrayList<>();
        for (AnfProperty p : props) if (!p.readonly()) mutableProps.add(p.name());
        List<Write> writes = new ArrayList<>();
        for (AnfMethod m : methods) {
            if ("constructor".equals(m.name())) continue;
            for (AnfBinding b : flat.get(m)) {
                AnfValue v = b.value();
                if (v instanceof UpdateProp up) writes.add(new Write(up.name(), up.value(), m));
                if (v instanceof AddOutput ao) {
                    for (int i = 0; i < ao.stateValues().size(); i++) {
                        if (i < mutableProps.size()) writes.add(new Write(mutableProps.get(i), ao.stateValues().get(i), m));
                    }
                }
            }
        }

        boolean grew = true;
        while (grew) {
            int before = keyProps.size();
            for (Write w : writes) {
                if (keyProps.contains(w.prop()) && isTrusted(w.value(), w.method(), new HashSet<>())) {
                    sourcesOf(w.value(), w.method(), keyProps, new HashSet<>());
                }
            }
            grew = keyProps.size() != before;
        }

        Set<String> mutable = new HashSet<>(mutableProps);
        for (AnfMethod m : methods) {
            for (AnfBinding b : flat.get(m)) {
                if (b.value() instanceof Call c && "verifyRabinSig".equals(c.func()) && c.args().size() >= 4
                    && !isTrusted(c.args().get(3), m, new HashSet<>())) {
                    throw new RuntimeException("IR validation: method '" + m.name() + "': "
                        + Validate.RABIN_PUBKEY_PROVENANCE_MESSAGE);
                }
            }
            for (Write w : writes) {
                if (w.method() != m || !keyProps.contains(w.prop()) || !mutable.contains(w.prop())) continue;
                if (!isTrusted(w.value(), m, new HashSet<>())) {
                    throw new RuntimeException("IR validation: method '" + m.name() + "': "
                        + Validate.rabinKeyWriteMessage(w.prop()));
                }
            }
        }
    }

    private boolean isTrusted(String ref, AnfMethod m, Set<String> visiting) {
        List<AnfValue> values = byName.get(m).get(ref);
        if (values == null || visiting.contains(ref)) return false;
        visiting.add(ref);
        boolean ok = true;
        for (AnfValue v : values) {
            if (!trustedValue(v, m, visiting)) {
                ok = false;
                break;
            }
        }
        visiting.remove(ref);
        return ok;
    }

    private boolean trustedValue(AnfValue v, AnfMethod m, Set<String> visiting) {
        if (v instanceof LoadProp) return true;
        if (v instanceof LoadConst lc) {
            if (lc.value() instanceof BigIntConst) return true;
            String ref = refOf(v);
            return ref != null && isTrusted(ref, m, visiting);
        }
        if (v instanceof LoadParam lp) {
            if (!isPrivate(m)) return false;
            int idx = paramIndex(m, lp.name());
            return idx >= 0 && trustedParams.get(m.name()).contains(idx);
        }
        if (v instanceof If iff) {
            // A single-result if (the per-property phi ANF lowering emits for an
            // if/else that writes a property) is its taken arm's last binding.
            if (iff.results() != null && !iff.results().isEmpty()) return false;
            List<AnfBinding> t = iff.thenBranch();
            List<AnfBinding> e = iff.elseBranch();
            if (t == null || t.isEmpty() || e == null || e.isEmpty()) return false;
            return isTrusted(t.get(t.size() - 1).name(), m, visiting)
                && isTrusted(e.get(e.size() - 1).name(), m, visiting);
        }
        return false;
    }

    private void sourcesOf(String ref, AnfMethod m, Set<String> out, Set<String> visiting) {
        if (!visiting.add(m.name() + "\0" + ref)) return;
        for (AnfValue v : byName.get(m).getOrDefault(ref, List.of())) {
            if (v instanceof LoadProp lp) {
                out.add(lp.name());
            } else if (refOf(v) != null) {
                sourcesOf(refOf(v), m, out, visiting);
            } else if (v instanceof If iff) {
                for (List<AnfBinding> arm : List.of(
                        iff.thenBranch() == null ? List.<AnfBinding>of() : iff.thenBranch(),
                        iff.elseBranch() == null ? List.<AnfBinding>of() : iff.elseBranch())) {
                    if (!arm.isEmpty()) sourcesOf(arm.get(arm.size() - 1).name(), m, out, visiting);
                }
            } else if (v instanceof LoadParam p && isPrivate(m)) {
                int idx = paramIndex(m, p.name());
                for (Site s : callSites.getOrDefault(m.name(), List.of())) {
                    if (idx >= 0 && idx < s.args().size()) sourcesOf(s.args().get(idx), s.method(), out, visiting);
                }
            }
        }
    }
}
