package frontend

import (
	"math/big"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// N-128 — constant folding must not erase a loop's Start and Step.
//
// `foldValue`'s "loop" arm rebuilt the node by hand, copying Count, IterVar and
// Body and dropping StartRaw, Start and Step. A loop that does not begin at 0,
// or that counts down, therefore came out of the folder as a zero-start
// step-1 loop, and the unroller produced a DIFFERENT NUMBER.
//
// Measured on the user-facing default (folding ON) before the fix:
//
//	for (let i = 3n; i < 7n; i++) acc += i     3+4+5+6 = 18   ts 0112   go 56 (=6)
//	for (let j = 5n; j > 1n; j--) acc += j     5+4+3+2 = 14   ts 5e     go 56 (=6)
//
// Both Go values are 0+1+2+3: the loop the folder emitted, not the loop the
// author wrote. With `--disable-constant-folding` the two tiers agreed exactly,
// which is why the golden corpus — stamped fold-OFF — never saw it, and why the
// fold-ON parity job did not either: no fixture has a non-zero-start or a
// countdown loop (R-102).
//
// The reference tier folds with a spread (`{ ...value, body: foldedBody }`), so
// every field survives by construction. This is the same hand-copied-subset
// shape as R-082 and N-086.
func TestFoldConstants_LoopPreservesStartAndStep(t *testing.T) {
	cases := []struct {
		name  string
		start int64
		step  int
		count int
	}{
		{"non-zero start, counting up", 3, 1, 4},
		{"countdown", 5, -1, 4},
		{"zero start (the historical shape)", 0, 1, 4},
		{"non-unit negative step", 9, -3, 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := big.NewInt(tc.start)
			program := &ir.ANFProgram{
				ContractName: "LoopFields",
				Methods: []ir.ANFMethod{{
					Name:     "verify",
					IsPublic: true,
					Body: []ir.ANFBinding{{
						Name: "t0",
						Value: ir.ANFValue{
							Kind:     "loop",
							Count:    tc.count,
							IterVar:  "i",
							Start:    start,
							StartRaw: []byte("3"),
							Step:     tc.step,
							Body:     []ir.ANFBinding{},
						},
					}},
				}},
			}

			folded := FoldConstants(program)

			var loop *ir.ANFValue
			for i := range folded.Methods[0].Body {
				if folded.Methods[0].Body[i].Value.Kind == "loop" {
					loop = &folded.Methods[0].Body[i].Value
				}
			}
			if loop == nil {
				t.Fatal("the loop binding did not survive folding at all")
			}

			if loop.Count != tc.count {
				t.Errorf("Count: got %d, want %d", loop.Count, tc.count)
			}
			if loop.Step != tc.step {
				t.Errorf("Step: got %d, want %d — a dropped Step turns a countdown "+
					"into a count-up and the unrolled loop computes a different value",
					loop.Step, tc.step)
			}
			if loop.Start == nil {
				t.Fatalf("Start: got nil, want %d — a dropped Start makes every loop "+
					"begin at 0", tc.start)
			}
			if loop.Start.Cmp(start) != 0 {
				t.Errorf("Start: got %s, want %d", loop.Start, tc.start)
			}
			if string(loop.StartRaw) != "3" {
				t.Errorf("StartRaw: got %q, want %q — the raw form is what the "+
					"canonical JSON round-trip re-emits", string(loop.StartRaw), "3")
			}
		})
	}
}
