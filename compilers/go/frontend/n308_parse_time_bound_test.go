package frontend

// N-308: three bracket-free .runar.ts shapes kept tree-sitter's own error
// recovery quadratic at MAX_SOURCE_BYTES (ts_subtree_summarize_children under
// ts_parser__recover, inside the vendored C, before any Go code runs):
//   closure_rs  `|| || … a`        >162 s CPU
//   lambda_py   `lambda: lambda: … a` >147 s CPU
//   logic_py    `a and a and … a`  >137 s CPU
// N-181's fix was to the Go-side walks and cannot reach them.
//
// What this proves: each shape, filling MAX_SOURCE_BYTES, is refused within
// the N-181 CPU budget, and refused by the parse bound with its own
// diagnostic (so a regression that merely gets slower but stays under the
// budget does not pass as a plain syntax error). It also proves a valid
// source of about the same size is NOT refused by the bound.
// What it does NOT prove: that no other shape is quadratic in tree-sitter
// (the bound covers any such shape by construction, but only these three are
// measured), anything about the other surfaces or tiers, or that the bound
// holds on a host so overloaded that a valid source's parse exceeds it — the
// bound is wall-clock, because the go-tree-sitter binding exposes no
// operation counter (see tsParseTimeLimit).

import (
	"strings"
	"testing"
)

const n308Diag = "source too complex to parse"

func TestN308QuadraticRecoveryShapesRefusedByParseBound(t *testing.T) {
	big := func(unit string) string { return strings.Repeat(unit, n181Cap/len(unit)) }
	shapes := []struct{ name, expr string }{
		{"closure_rs", big("|| ") + "a"},
		{"lambda_py", big("lambda: ") + "a"},
		{"logic_py", "a" + big(" and a")},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			src := n181TS("", s.expr)
			res := n181Check(t, s.name, "P.runar.ts", src, true)
			if !strings.Contains(strings.Join(res.ErrorStrings(), "\n"), n308Diag) {
				t.Fatalf("%s: refused, but not by the parse bound: %v", s.name, res.ErrorStrings())
			}
		})
	}
}

// A valid contract near MAX_SOURCE_BYTES parses well inside the bound.
func TestN308ValidLargeSourceNotRefusedByParseBound(t *testing.T) {
	stmt := " assert(a == b);\n"
	src := n181TS(strings.Repeat(stmt, n181Cap/len(stmt)), "a")
	res := ParseSource([]byte(src), "P.runar.ts")
	for _, e := range res.ErrorStrings() {
		if strings.Contains(e, n308Diag) {
			t.Fatalf("valid %d-byte source refused by the parse bound: %s", len(src), e)
		}
	}
	if res.Contract == nil {
		t.Fatalf("valid source not parsed: %v", res.ErrorStrings())
	}
}
