package frontend

import (
	"strings"
	"testing"
	"time"
)

// checkGoNumericLiterals (the F-026 integer-literal check every .runar.go
// source passes through before go/parser) converted the WHOLE source to a
// string once per numeric token — `scanNumberEnd(string(source), start)` —
// so its cost was (number of literals) x (source size): a 4 MiB source of
// `[0]`s ran for minutes before any parser saw it, well inside
// MAX_SOURCE_BYTES. The fix converts once.
//
// What this proves: a ~1 MiB source holding ~340k integer literals is checked
// in well under the budget (linear time), and every literal is still accepted.
// What it does NOT prove: anything about go/parser or the converter, which run
// after this check; the budget is generous so a slow CI runner does not flake.
func TestGoNumericLiteralCheckIsLinear(t *testing.T) {
	const literals = 340_000
	var b strings.Builder
	b.WriteString("package contract\n\nvar table = []int{")
	for i := 0; i < literals; i++ {
		b.WriteString("0, ")
	}
	b.WriteString("}\n")
	source := []byte(b.String())

	start := time.Now()
	diags := checkGoNumericLiterals(source, "Table.runar.go")
	elapsed := time.Since(start)

	if len(diags) != 0 {
		t.Fatalf("valid integer literals refused: %d diagnostics, first %q", len(diags), diags[0].Message)
	}
	const budget = 10 * time.Second
	if elapsed > budget {
		t.Fatalf("checking %d literals in a %d-byte source took %v (budget %v): the scan is not linear",
			literals, len(source), elapsed, budget)
	}
	t.Logf("%d literals, %d bytes: %v", literals, len(source), elapsed)
}
