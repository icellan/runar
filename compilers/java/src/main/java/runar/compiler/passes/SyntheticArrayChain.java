package runar.compiler.passes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import runar.compiler.ir.anf.AnfProperty;

/**
 * N-096: the {@code syntheticArrayChain} validity rule for {@code --ir} input.
 * Port of {@code packages/runar-compiler/src/ir/synthetic-array-chain.ts}: same
 * rule, same order, same words
 * ({@code conformance/negatives/ir-synthetic-array-chain.test.ts}).
 *
 * <ol>
 *   <li>at most {@link #MAX_DEPTH} levels (the regrouper's 1024 passes are the
 *       only nesting bound the pipeline has);</li>
 *   <li>every level has {@code 0 <= index < length};</li>
 *   <li>level k's base is level k-1's {@code <base>__<index>}, and the property
 *       is named {@code <innermost base>__<innermost index>};</li>
 *   <li>the leaves sharing a root are exactly one expansion: contiguous,
 *       row-major from element 0, one type and one list of level lengths, and
 *       complete.</li>
 * </ol>
 *
 * <p>Before the rule this tier published the F-105 probe's 1100-level
 * property as a scalar constructor parameter.
 */
public final class SyntheticArrayChain {

    /** The deepest chain the regrouper's 1024-pass cap can consume. */
    public static final int MAX_DEPTH = 1023;

    private SyntheticArrayChain() {}

    private static RuntimeException refuse(String prop, String detail) {
        return new RuntimeException(
            "IR validation: malformed syntheticArrayChain on property '" + prop + "': " + detail);
    }

    private static final class Family {
        final String root;
        final String type;
        final int[] lengths;
        int[] tuple;
        String last;

        Family(String root, String type, int[] lengths, int[] tuple, String last) {
            this.root = root;
            this.type = type;
            this.lengths = lengths;
            this.tuple = tuple;
            this.last = last;
        }

        boolean complete() {
            for (int k = 0; k < tuple.length; k++) {
                if (tuple[k] != lengths[k] - 1) return false;
            }
            return true;
        }

        int[] next() {
            int[] t = tuple.clone();
            for (int k = t.length - 1; k >= 0; k--) {
                if (t[k] + 1 < lengths[k]) {
                    t[k]++;
                    return t;
                }
                t[k] = 0;
            }
            return t;
        }
    }

    private static String leafName(String root, int[] tuple) {
        StringBuilder b = new StringBuilder(root);
        for (int i : tuple) b.append("__").append(i);
        return b.toString();
    }

    private static String expects(String root, String type, int[] lengths, int[] tuple) {
        List<String> ls = new ArrayList<>();
        for (int l : lengths) ls.add(Integer.toString(l));
        return "'" + root + "' expects its element '" + leafName(root, tuple) + "' here (type " + type
            + ", level lengths [" + String.join(", ", ls) + "])";
    }

    private static void checkLevels(String name, List<AnfProperty.SyntheticArrayLevel> chain) {
        if (chain.size() > MAX_DEPTH) {
            throw refuse(name, chain.size() + " levels exceed the limit of " + MAX_DEPTH);
        }
        for (int k = 0; k < chain.size(); k++) {
            AnfProperty.SyntheticArrayLevel lvl = chain.get(k);
            if (!(lvl.index() >= 0 && lvl.index() < lvl.length())) {
                throw refuse(name, "level " + k + " has index " + lvl.index() + " and length " + lvl.length()
                    + "; expand-fixed-arrays writes 0 <= index < length");
            }
            if (k > 0) {
                AnfProperty.SyntheticArrayLevel prev = chain.get(k - 1);
                String want = prev.base() + "__" + prev.index();
                if (!want.equals(lvl.base())) {
                    throw refuse(name, "level " + k + " has base '" + lvl.base()
                        + "'; expand-fixed-arrays writes '" + want + "'");
                }
            }
        }
        AnfProperty.SyntheticArrayLevel inner = chain.get(chain.size() - 1);
        String want = inner.base() + "__" + inner.index();
        if (!want.equals(name)) {
            throw refuse(name, "its innermost level is element " + inner.index() + " of '" + inner.base()
                + "'; expand-fixed-arrays names that property '" + want + "'");
        }
    }

    /** Throws the shared diagnostic for the first chain the rule refuses. */
    public static void check(List<AnfProperty> props) {
        Family open = null;
        Set<String> seen = new HashSet<>();

        for (AnfProperty p : props) {
            List<AnfProperty.SyntheticArrayLevel> chain =
                p.syntheticArrayChain() == null ? List.of() : p.syntheticArrayChain();
            if (open != null && (chain.isEmpty() || !open.root.equals(chain.get(0).base()))) {
                close(open);
                open = null;
            }
            if (chain.isEmpty()) continue;

            checkLevels(p.name(), chain);
            int[] tuple = new int[chain.size()];
            int[] lengths = new int[chain.size()];
            for (int k = 0; k < chain.size(); k++) {
                tuple[k] = chain.get(k).index();
                lengths[k] = chain.get(k).length();
            }

            if (open != null) {
                if (open.complete()) {
                    throw refuse(p.name(), "'" + open.root + "' already ended before this property");
                }
                int[] want = open.next();
                if (!p.type().equals(open.type) || !Arrays.equals(lengths, open.lengths)
                        || !Arrays.equals(tuple, want)) {
                    throw refuse(p.name(), expects(open.root, open.type, open.lengths, want));
                }
                open.tuple = want;
                open.last = p.name();
                continue;
            }

            String root = chain.get(0).base();
            if (seen.contains(root)) {
                throw refuse(p.name(), "'" + root + "' already ended before this property");
            }
            int[] start = new int[chain.size()];
            if (!Arrays.equals(tuple, start)) {
                throw refuse(p.name(), expects(root, p.type(), lengths, start));
            }
            seen.add(root);
            open = new Family(root, p.type(), lengths, tuple, p.name());
        }
        if (open != null) close(open);
    }

    private static void close(Family f) {
        if (!f.complete()) {
            throw refuse(f.last, "'" + f.root + "' ends here, before its element '"
                + leafName(f.root, f.next()) + "'");
        }
    }
}
