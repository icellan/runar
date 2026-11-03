package frontend

// N-311: measure (A) of MAX_SOURCE_NESTING counts intersection / union type
// nesting (user decision R117).
//
// tree-sitter parses a `.runar.ts` annotation `&&&…&Int` as a valid
// right-nested intersection_type chain, one level per `&`, and measure (A)
// used to count no type operator, so tsParseNestingViolation walked the whole
// chain: about 208 MB of Go heap at 256k levels, all of it before any
// diagnostic. Each operand of an intersection / union type now adds one level,
// except a same-operator left operand, which is how tree-sitter spells the
// continuation of one flat list (`A & B & C` is intersection(intersection(A,
// B), C) here and a single three-operand IntersectionType in the TS
// reference).
//
// What these tests prove: the parenthesised shape the TS reference pins
// (n = 127 not refused for nesting, n = 128 refused, for `&`, `|` and both)
// gives the same verdict here; a flat 500-operand intersection is one level;
// the tree-sitter-only `&&&…Int` chain is refused with the shared diagnostic;
// and at 256k levels the Go-heap allocation across ParseSource is a few MB.
//
// What they do NOT prove: tree-sitter's own C allocations for the parse
// (outside the Go heap, so not in runtime.MemStats), nor the verdict of the
// other tiers (conformance/negatives/n311-type-operator-nesting-parity.test.ts).

import (
	"runtime"
	"strings"
	"testing"
)

const n311Head = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint, b: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n"

func n311Nested(n int, ops ...string) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("(bigint " + ops[i%len(ops)] + " ")
	}
	b.WriteString("bigint" + strings.Repeat(")", n))
	return []byte(strings.Replace(n311Head, "{T}", b.String(), 1))
}

func TestN311_TsTypeOperatorNestingBoundary(t *testing.T) {
	for _, ops := range [][]string{{"&"}, {"|"}, {"&", "|"}} {
		name := strings.Join(ops, " ")
		if res := ParseSource(n311Nested(MaxSourceNesting-1, ops...), "P.runar.ts"); f213HasDiag(res) {
			t.Errorf("%s n=%d: refused for nesting, want within measure (A): %v", name, MaxSourceNesting-1, res.ErrorStrings())
		}
		if res := ParseSource(n311Nested(MaxSourceNesting, ops...), "P.runar.ts"); !f213HasDiag(res) || res.Contract != nil {
			t.Errorf("%s n=%d: want refusal with %q, got contract=%v errors %v", name, MaxSourceNesting, f213Diag, res.Contract != nil, res.ErrorStrings())
		}
	}
}

func TestN311_TsFlatIntersectionIsOneLevel(t *testing.T) {
	src := strings.Replace(n311Head, "{T}", strings.Repeat("bigint & ", 499)+"bigint", 1)
	if res := ParseSource([]byte(src), "P.runar.ts"); f213HasDiag(res) {
		t.Fatalf("a flat 500-operand intersection was refused for nesting: %v", res.ErrorStrings())
	}
}

func n311AmpChain(n int) []byte {
	return []byte(strings.Replace(n311Head, "{T}", strings.Repeat("&", n)+"Int", 1))
}

func TestN311_TsAmpersandChainRefused(t *testing.T) {
	if res := ParseSource(n311AmpChain(300), "P.runar.ts"); !f213HasDiag(res) || res.Contract != nil {
		t.Fatalf("want refusal with %q, got contract=%v errors %v", f213Diag, res.Contract != nil, res.ErrorStrings())
	}
}

// The measure-(A) walk must stop near the limit instead of following a
// 256k-deep chain. Before N-311 this allocated ~208 MB of Go heap (TotalAlloc);
// the bound is generous on purpose — the point is "stops near the limit", not
// a byte count. tree-sitter's C allocations are not in MemStats.
func TestN311_TsAmpersandChainWalkIsBounded(t *testing.T) {
	src := n311AmpChain(256 * 1024)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res := ParseSource(src, "P.runar.ts")
	runtime.ReadMemStats(&after)
	if !f213HasDiag(res) || res.Contract != nil {
		t.Errorf("want refusal with %q, got contract=%v errors %v", f213Diag, res.Contract != nil, res.ErrorStrings())
	}
	const bound = 16 << 20
	got := after.TotalAlloc - before.TotalAlloc
	t.Logf("ParseSource allocated %d bytes of Go heap", got)
	if got > bound {
		t.Errorf("ParseSource allocated %d bytes of Go heap on a 256k-level chain, want <= %d", got, bound)
	}
}
