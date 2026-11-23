package runar.compiler;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.Loop;

/**
 * PQ-F1: the artifact's {@code pqPubKeyParams} — constructor params passed
 * directly as the public key of a post-quantum verifier, with the exact byte
 * length that verifier needs. Computed from the final ANF exactly as the TS
 * reference ({@code packages/runar-ir-schema/src/pq-pubkey.ts}): every method,
 * nested if / loop bodies, {@code @ref:} aliases, pk = the verifier call's
 * third arg; kept to constructor params, deduplicated on (name, scheme),
 * sorted by (index, scheme).
 */
final class PqPubKeyParams {
    private PqPubKeyParams() {}

    /** One entry; field order is the wire key order. */
    record Entry(int index, String name, String scheme, int length) {}

    /** pk bytes each verifier splits its pk operand at: WOTS+ 32||32, SLH-DSA n||n. */
    private static final Map<String, Integer> PQ_PUBKEY_BYTES = Map.of(
        "verifyWOTS", 64,
        "verifySLHDSA_SHA2_128s", 32,
        "verifySLHDSA_SHA2_128f", 32,
        "verifySLHDSA_SHA2_192s", 48,
        "verifySLHDSA_SHA2_192f", 48,
        "verifySLHDSA_SHA2_256s", 64,
        "verifySLHDSA_SHA2_256f", 64);

    static List<Entry> compute(AnfProgram anf, List<String> ctorNames) {
        List<Entry> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (AnfMethod m : anf.methods()) {
            walk(m.body(), new HashMap<>(), ctorNames, seen, out);
        }
        out.sort(Comparator.comparingInt(Entry::index).thenComparing(Entry::scheme));
        return out;
    }

    private static void walk(List<AnfBinding> bindings, Map<String, String> propOf,
                             List<String> ctorNames, Set<String> seen, List<Entry> out) {
        if (bindings == null) return;
        for (AnfBinding b : bindings) {
            var v = b.value();
            if (v instanceof LoadProp lp) {
                propOf.put(b.name(), lp.name());
            } else if (v instanceof LoadConst lc && lc.value() instanceof BytesConst bc
                && bc.hex() != null && bc.hex().startsWith("@ref:")) {
                String target = propOf.get(bc.hex().substring(5));
                if (target != null) propOf.put(b.name(), target);
            } else if (v instanceof Call c && PQ_PUBKEY_BYTES.containsKey(c.func())
                && c.args() != null && c.args().size() > 2) {
                String prop = propOf.get(c.args().get(2));
                int index = prop == null ? -1 : ctorNames.indexOf(prop);
                if (index >= 0 && seen.add(prop + "\u0000" + c.func())) {
                    out.add(new Entry(index, prop, c.func(), PQ_PUBKEY_BYTES.get(c.func())));
                }
            } else if (v instanceof If i) {
                walk(i.thenBranch(), propOf, ctorNames, seen, out);
                walk(i.elseBranch(), propOf, ctorNames, seen, out);
            } else if (v instanceof Loop l) {
                walk(l.body(), propOf, ctorNames, seen, out);
            }
        }
    }
}
