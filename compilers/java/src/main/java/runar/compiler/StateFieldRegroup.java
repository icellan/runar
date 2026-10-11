package runar.compiler;

import java.util.ArrayList;
import java.util.List;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.AnfProperty.SyntheticArrayLevel;

/**
 * N-086: regroup synthetic {@code FixedArray} state-field leaves back into
 * one logical {@code stateFields} entry, so the Java artifact matches every
 * other tier's.
 *
 * <p>Pass 3b ({@code ExpandFixedArrays}) desugars a property like
 * {@code table: FixedArray<bigint, 4>} into 4 scalar siblings
 * {@code table__0..table__3} before ANF lowering, and tags each leaf's
 * {@link AnfProperty#syntheticArrayChain()} with the nesting level(s) it came
 * from (N-095). Every other tier's artifact assembler reads that chain back
 * off the ANF program to republish one {@code fixedArray}-tagged entry for
 * the user-facing ABI/state view; this tier's {@code Cli#writeArtifact}
 * instead published each leaf as its own scalar {@code stateFields} entry, on
 * both the {@code --source} and the {@code --ir} path, because it never
 * consulted the chain.
 *
 * <p>Direct port of the TS reference's {@code regroupSyntheticRuns} in
 * {@code packages/runar-compiler/src/artifact/assembler.ts}, equivalently
 * {@code compilers/go/compiler/regroup.go}: same algorithm, same grouping
 * rules, same refusal messages for a chain pass 3b could not have written.
 * Grouping is marker-driven, not pattern-driven — a hand-named
 * {@code foo__0}, {@code foo__1} pair with no chain is left as two
 * independent scalars.
 *
 * <p>Scope: {@code stateFields} only (N-086's testable assertion). The
 * constructor ABI ({@code abi.constructor.params}) still publishes expanded
 * leaves as scalars on this tier — a sibling gap, not this item.
 */
final class StateFieldRegroup {

    private StateFieldRegroup() {}

    /** One grouped (or still-scalar) output entry. */
    record Grouped(String name, String type, int index, Object initialValue, FixedArray fixedArray) {}

    /** Mirrors the wire shape {@code {elementType, length, syntheticNames}}. */
    record FixedArray(String elementType, int length, List<String> syntheticNames) {}

    /**
     * Regroup the mutable (non-readonly) properties of {@code properties}
     * into their published {@code stateFields} shape. {@code index} on each
     * output is the ORIGINAL property's position in the full properties
     * list (constructor arg order), matching every other tier.
     */
    static List<Grouped> run(List<AnfProperty> properties) {
        List<Entry> flat = new ArrayList<>();
        for (int i = 0; i < properties.size(); i++) {
            AnfProperty p = properties.get(i);
            if (p.readonly()) continue;
            Entry e = new Entry();
            e.name = p.name();
            e.type = p.type();
            e.chain = p.syntheticArrayChain() == null ? List.of() : p.syntheticArrayChain();
            e.initialValue = p.initialValue();
            e.index = i;
            flat.add(e);
        }
        List<Entry> regrouped = regroupSyntheticRuns(flat);
        List<Grouped> out = new ArrayList<>(regrouped.size());
        for (Entry e : regrouped) {
            out.add(new Grouped(e.name, e.type, e.index, e.initialValue, e.fixedArray));
        }
        return out;
    }

    // -----------------------------------------------------------------
    // Internal regroup loop (direct port of regroupOnePass/regroupSyntheticRuns)
    // -----------------------------------------------------------------

    private static final class Entry {
        String name;
        String type;
        List<SyntheticArrayLevel> chain;
        Object initialValue;
        FixedArray fixedArray;
        int index;
    }

    private record Pass(List<Entry> out, boolean changed) {}

    private static List<Entry> regroupSyntheticRuns(List<Entry> entries) {
        List<Entry> current = entries;
        for (int iter = 0; iter < 1024; iter++) {
            Pass pass = regroupOnePass(current);
            current = pass.out();
            if (!pass.changed()) return current;
        }
        throw new RuntimeException("regroupSyntheticRuns: exceeded iteration cap (pathological chain nesting?)");
    }

    private static Pass regroupOnePass(List<Entry> entries) {
        List<Entry> out = new ArrayList<>();
        boolean changed = false;
        int i = 0;
        while (i < entries.size()) {
            Entry entry = entries.get(i);
            int chainLen = entry.chain.size();
            if (chainLen == 0) {
                out.add(entry);
                i++;
                continue;
            }
            SyntheticArrayLevel marker = entry.chain.get(chainLen - 1);
            if (marker.index() != 0) {
                // R-289: a sibling reaching the head of the loop has no run head
                // before it — the head consumes its whole run and advances past
                // it, so index != 0 here means the chain did not come from pass
                // 3b. Publishing it as a scalar would be a wrong ABI with no
                // diagnostic.
                throw new RuntimeException(
                    "malformed synthetic-array chain on '" + entry.name + "': element " + marker.index()
                        + " of '" + marker.base() + "' appears without the element 0 that starts its run. "
                        + "Synthetic-array chains are written by the expand-fixed-arrays pass; "
                        + "this IR did not come from it.");
            }

            List<Entry> runEntries = new ArrayList<>();
            runEntries.add(entry);
            int k = 1;
            int j = i + 1;
            while (j < entries.size() && k < marker.length()) {
                Entry next = entries.get(j);
                if (next.chain.isEmpty()) break;
                SyntheticArrayLevel m2 = next.chain.get(next.chain.size() - 1);
                if (!m2.base().equals(marker.base()) || m2.length() != marker.length()
                        || m2.index() != k || !next.type.equals(entry.type)) {
                    break;
                }
                runEntries.add(next);
                k++;
                j++;
            }

            if (runEntries.size() != marker.length()) {
                // R-289: a well-formed expansion always emits all N siblings
                // contiguously, so a short run means the chain was not written
                // by pass 3b.
                throw new RuntimeException(
                    "malformed synthetic-array chain on '" + entry.name + "': '" + marker.base() + "' declares "
                        + marker.length() + " elements but the contiguous run has " + runEntries.size() + ". "
                        + "Synthetic-array chains are written by the expand-fixed-arrays pass; "
                        + "this IR did not come from it.");
            }

            String innerType = entry.type;
            String groupedType = "FixedArray<" + innerType + ", " + marker.length() + ">";

            List<String> syntheticNames = new ArrayList<>();
            for (Entry e : runEntries) {
                if (e.fixedArray != null) {
                    syntheticNames.addAll(e.fixedArray.syntheticNames());
                } else {
                    syntheticNames.add(e.name);
                }
            }

            boolean allHaveInit = true;
            for (Entry e : runEntries) {
                if (e.initialValue == null) {
                    allHaveInit = false;
                    break;
                }
            }
            Object collapsedInit = null;
            if (allHaveInit) {
                List<Object> arr = new ArrayList<>(runEntries.size());
                for (Entry e : runEntries) arr.add(e.initialValue);
                collapsedInit = arr;
            }

            Entry grouped = new Entry();
            grouped.name = marker.base();
            grouped.type = groupedType;
            grouped.chain = entry.chain.subList(0, chainLen - 1);
            grouped.fixedArray = new FixedArray(innerType, marker.length(), syntheticNames);
            grouped.index = runEntries.get(0).index;
            grouped.initialValue = collapsedInit;

            out.add(grouped);
            i = j;
            changed = true;
        }
        return new Pass(out, changed);
    }
}
