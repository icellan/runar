package ir

import (
	"fmt"
	"strconv"
	"strings"
)

// N-096 — the syntheticArrayChain validity rule for --ir input. Port of
// packages/runar-compiler/src/ir/synthetic-array-chain.ts: same rule, same
// order, same words (conformance/negatives/ir-synthetic-array-chain.test.ts).
//
// The chain is what expand-fixed-arrays hangs off each scalar leaf of a
// FixedArray property and what the artifact regrouper consumes one level per
// pass. A chain the pass could not have written made this tier PANIC in
// regroupSyntheticRuns (exit 2) while the other tiers split four ways.
//
//  1. at most MaxSyntheticArrayDepth levels (the regrouper's 1024 passes are
//     the only nesting bound the pipeline has);
//  2. every level has 0 <= index < length;
//  3. level k's base is level k-1's `<base>__<index>`, and the property is
//     named `<innermost base>__<innermost index>`;
//  4. the leaves sharing a root are exactly one expansion: contiguous,
//     row-major from element 0, one type and one list of level lengths, and
//     complete.

// MaxSyntheticArrayDepth is the deepest chain the regrouper's 1024-pass cap
// can consume.
const MaxSyntheticArrayDepth = 1023

func chainRefuse(prop, detail string) error {
	return fmt.Errorf("IR validation: malformed syntheticArrayChain on property '%s': %s", prop, detail)
}

type chainFamily struct {
	root    string
	typ     string
	lengths []int
	tuple   []int
	last    string
}

func chainLeafName(root string, tuple []int) string {
	var b strings.Builder
	b.WriteString(root)
	for _, i := range tuple {
		b.WriteString("__")
		b.WriteString(strconv.Itoa(i))
	}
	return b.String()
}

func (f *chainFamily) complete() bool {
	for k, i := range f.tuple {
		if i != f.lengths[k]-1 {
			return false
		}
	}
	return true
}

func (f *chainFamily) next() []int {
	t := append([]int(nil), f.tuple...)
	for k := len(t) - 1; k >= 0; k-- {
		if t[k]+1 < f.lengths[k] {
			t[k]++
			return t
		}
		t[k] = 0
	}
	return t
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func chainExpects(root, typ string, lengths, tuple []int) string {
	parts := make([]string, len(lengths))
	for i, l := range lengths {
		parts[i] = strconv.Itoa(l)
	}
	return fmt.Sprintf("'%s' expects its element '%s' here (type %s, level lengths [%s])",
		root, chainLeafName(root, tuple), typ, strings.Join(parts, ", "))
}

func checkChainLevels(name string, chain []ANFSyntheticArrayLevel) error {
	if len(chain) > MaxSyntheticArrayDepth {
		return chainRefuse(name, fmt.Sprintf("%d levels exceed the limit of %d", len(chain), MaxSyntheticArrayDepth))
	}
	for k, lvl := range chain {
		if !(lvl.Index >= 0 && lvl.Index < lvl.Length) {
			return chainRefuse(name, fmt.Sprintf(
				"level %d has index %d and length %d; expand-fixed-arrays writes 0 <= index < length",
				k, lvl.Index, lvl.Length))
		}
		if k > 0 {
			want := chain[k-1].Base + "__" + strconv.Itoa(chain[k-1].Index)
			if lvl.Base != want {
				return chainRefuse(name, fmt.Sprintf("level %d has base '%s'; expand-fixed-arrays writes '%s'", k, lvl.Base, want))
			}
		}
	}
	inner := chain[len(chain)-1]
	want := inner.Base + "__" + strconv.Itoa(inner.Index)
	if name != want {
		return chainRefuse(name, fmt.Sprintf(
			"its innermost level is element %d of '%s'; expand-fixed-arrays names that property '%s'",
			inner.Index, inner.Base, want))
	}
	return nil
}

// AssertSyntheticArrayChains returns the shared diagnostic for the first
// chain the rule refuses, or nil.
func AssertSyntheticArrayChains(program *ANFProgram) error {
	var open *chainFamily
	seen := map[string]bool{}

	closeFamily := func() error {
		if open != nil && !open.complete() {
			return chainRefuse(open.last, fmt.Sprintf("'%s' ends here, before its element '%s'",
				open.root, chainLeafName(open.root, open.next())))
		}
		open = nil
		return nil
	}

	for _, prop := range program.Properties {
		chain := prop.SyntheticArrayChain
		if open != nil && (len(chain) == 0 || chain[0].Base != open.root) {
			if err := closeFamily(); err != nil {
				return err
			}
		}
		if len(chain) == 0 {
			continue
		}
		if err := checkChainLevels(prop.Name, chain); err != nil {
			return err
		}
		tuple := make([]int, len(chain))
		lengths := make([]int, len(chain))
		for k, lvl := range chain {
			tuple[k] = lvl.Index
			lengths[k] = lvl.Length
		}

		if open != nil {
			if open.complete() {
				return chainRefuse(prop.Name, fmt.Sprintf("'%s' already ended before this property", open.root))
			}
			want := open.next()
			if prop.Type != open.typ || !intsEqual(lengths, open.lengths) || !intsEqual(tuple, want) {
				return chainRefuse(prop.Name, chainExpects(open.root, open.typ, open.lengths, want))
			}
			open.tuple = want
			open.last = prop.Name
			continue
		}

		root := chain[0].Base
		if seen[root] {
			return chainRefuse(prop.Name, fmt.Sprintf("'%s' already ended before this property", root))
		}
		start := make([]int, len(chain))
		if !intsEqual(tuple, start) {
			return chainRefuse(prop.Name, chainExpects(root, prop.Type, lengths, start))
		}
		seen[root] = true
		open = &chainFamily{root: root, typ: prop.Type, lengths: lengths, tuple: tuple, last: prop.Name}
	}
	return closeFamily()
}
