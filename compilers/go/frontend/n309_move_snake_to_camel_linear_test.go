package frontend

// N-309: snakeToCamel (.runar.move) grew its result with `result += ...`, which
// copies the whole string per segment: quadratic on a long `a_a_a_…` identifier
// (20k segments 0.1 s, 80k 0.8 s, 4 MiB far beyond any budget).
//
// What this proves: a .runar.move source whose parameter name is a ~4 MiB
// snake_case identifier parses within the N-181 CPU budget, and snakeToCamel
// still yields the camelCase result. What it does NOT prove: anything about the
// other surfaces or tiers, or identifiers in positions other than a parameter.

import (
	"strings"
	"testing"
)

func TestN309MoveSnakeToCamelLinear(t *testing.T) {
	ident := strings.Repeat("a_", n181Cap/2-256) + "a"
	src := "module P {\n    resource struct P {\n        t: bigint,\n    }\n\n    public fun verify(contract: &P, " + ident + ": bigint) {\n        assert!(contract.t == 0, 0);\n    }\n}\n"
	n181Check(t, "move 4 MiB snake_case identifier", "P.runar.move", src, false)
}

func TestN309SnakeToCamelValues(t *testing.T) {
	for in, want := range map[string]string{
		"a": "a", "check_sig": "checkSig", "a_b_c": "aBC", "a__b": "aB", "_a": "A", "a_": "a", "pub_key_hash": "pubKeyHash",
	} {
		if got := snakeToCamel(in); got != want {
			t.Errorf("snakeToCamel(%q) = %q, want %q", in, got, want)
		}
	}
}
