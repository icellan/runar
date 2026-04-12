package compiler

import (
	"fmt"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// FixedArray re-grouping for the artifact ABI / stateFields.
//
// Pass 3b (expand-fixed-arrays) expands a property like
// `board: FixedArray<bigint, 9>` into 9 scalar siblings `board__0..board__8`.
// For nested arrays `grid: FixedArray<FixedArray<bigint, 2>, 2>` it expands
// into 4 scalar leaves `grid__0__0 .. grid__1__1`. Downstream passes (ANF,
// stack, emit) see and operate on those scalars.
//
// For the user-facing ABI and state-field list we re-group those synthetic
// siblings back into a single logical entry tagged `fixedArray` so the SDK
// can present the array-shaped API — including nested arrays.
//
// Grouping is marker-driven, NOT pattern-driven: every participating entry
// must carry a `SyntheticArrayChain` attached at expansion time. A
// user-written contract with hand-named properties `foo__0`, `foo__1`,
// `foo__2` of the same type will NOT be grouped — the chain is missing, so
// the regrouper leaves them as independent scalars.
//
// The regrouper runs iteratively: each pass collapses one level of the
// innermost FixedArray (peeling one entry off the end of every chain) and
// wraps the resulting group's type in one more `FixedArray<...,N>` layer.
// Repeat until no entry has any remaining chain. This is a direct port of
// TS `regroupSyntheticRuns` in `packages/runar-compiler/src/artifact/assembler.ts`.
// ---------------------------------------------------------------------------

// regroupEntry holds one entry going through the iterative regrouping
// loop. `chain` is the still-to-be-consumed nesting levels (innermost =
// last). `fixedArray` carries the grouped metadata for entries produced
// by a previous regroup pass.
type regroupEntry struct {
	name         string
	typ          string
	chain        []ir.ANFSyntheticArrayLevel
	initialValue interface{}
	fixedArray   *ABIFixedArray
	index        int
}

// regroupOnePass finds maximal runs whose innermost chain entries match
// (same base, same length, contiguous indices 0..length-1, same type)
// and collapses each into a single entry wrapping the type in one more
// FixedArray layer. Returns `changed=true` if at least one group was
// formed.
func regroupOnePass(entries []regroupEntry) ([]regroupEntry, bool) {
	var out []regroupEntry
	changed := false
	i := 0
	for i < len(entries) {
		entry := entries[i]
		chainLen := len(entry.chain)
		if chainLen == 0 {
			out = append(out, entry)
			i++
			continue
		}
		marker := entry.chain[chainLen-1]
		if marker.Index != 0 {
			out = append(out, entry)
			i++
			continue
		}

		// Greedily extend: every follower must share the same innermost
		// {base, length}, carry the expected index = k, and have the
		// identical current `typ` (so mixed-type runs cannot spuriously
		// collapse).
		runEntries := []regroupEntry{entry}
		k := 1
		j := i + 1
		for j < len(entries) && k < marker.Length {
			next := entries[j]
			if len(next.chain) == 0 {
				break
			}
			m2 := next.chain[len(next.chain)-1]
			if m2.Base != marker.Base || m2.Length != marker.Length || m2.Index != k || next.typ != entry.typ {
				break
			}
			runEntries = append(runEntries, next)
			k++
			j++
		}

		if len(runEntries) != marker.Length {
			// Partial or broken run — defensive. A well-formed expansion
			// always emits all N siblings contiguously, so this only
			// fires on bugs/malformed inputs.
			out = append(out, entry)
			i++
			continue
		}

		// Collapse this run into one intermediate entry.
		innerType := entry.typ
		groupedType := fmt.Sprintf("FixedArray<%s, %d>", innerType, marker.Length)

		var syntheticNames []string
		for _, e := range runEntries {
			if e.fixedArray != nil {
				syntheticNames = append(syntheticNames, e.fixedArray.SyntheticNames...)
			} else {
				syntheticNames = append(syntheticNames, e.name)
			}
		}

		// Collapse initial values: every child must have one.
		var collapsedInit interface{}
		allHaveInit := true
		for _, e := range runEntries {
			if e.initialValue == nil {
				allHaveInit = false
				break
			}
		}
		if allHaveInit {
			arr := make([]interface{}, len(runEntries))
			for idx, e := range runEntries {
				arr[idx] = e.initialValue
			}
			collapsedInit = arr
		}

		grouped := regroupEntry{
			name:  marker.Base,
			typ:   groupedType,
			chain: append([]ir.ANFSyntheticArrayLevel(nil), entry.chain[:chainLen-1]...),
			fixedArray: &ABIFixedArray{
				ElementType:    innerType,
				Length:         marker.Length,
				SyntheticNames: syntheticNames,
			},
			index: runEntries[0].index,
		}
		if collapsedInit != nil {
			grouped.initialValue = collapsedInit
		}

		out = append(out, grouped)
		i = j
		changed = true
	}
	return out, changed
}

// regroupSyntheticRuns iteratively regroups entries until no entry has
// any remaining chain. Each pass consumes one nesting level, innermost
// first. Panics if the iteration cap is exceeded (pathological nesting).
func regroupSyntheticRuns(entries []regroupEntry) []regroupEntry {
	current := entries
	for iter := 0; iter < 1024; iter++ {
		next, changed := regroupOnePass(current)
		current = next
		if !changed {
			return current
		}
	}
	panic("regroupSyntheticRuns: exceeded iteration cap (pathological chain nesting?)")
}
