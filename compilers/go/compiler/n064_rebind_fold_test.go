package compiler

// N-064 — constant folding must not fold with a constant a name no longer
// holds.
//
// The folder recorded a name's constant when a binding produced one and never
// dropped it. A name can be bound more than once, and the probes that showed
// it named a user local like an earlier compiler temp, so with folding ON (the
// default) later uses folded with a stale value: Rebind's guard became OP_TRUE
// (7600a0695151515177777777, spendable with any p > 0), RebindEq's became
// OP_FALSE, and a rebinding inside an if arm or a loop body leaked the same
// way past the if / into later iterations.
//
// N-065 changed how this is tested: the collision is now itself refused, so
// the four probe SOURCES no longer compile (asserted below). The fold must
// still be right for the ANF shape, so each probe's exact ANF — generated from
// the source with parse -> lowerToANF and no validator, in
// conformance/negatives/n064-collision-anf.json — is loaded through the IR
// loader and compiled with folding ON via CompileFromProgram. The pre-N-064
// folder turns that ANF into the probe's `staleFoldOn` script (verified on the
// TS reference folder); the current one must give `foldOff`.
//
// Proves: this tier's folder, on each probe's collision ANF, emits the same
// bytes as with folding OFF, pinned to the fold-OFF bytes every tier emits,
// and the probe sources are refused with the N-065 diagnostic. Does NOT prove
// on-chain behaviour — the Spend-engine proof is
// packages/runar-testing/src/__tests__/n064-rebind-fold-spend.test.ts.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// n064CollidingLocal is the local each probe spells like a temp.
var n064CollidingLocal = map[string]string{
	"Rebind": "t1", "RebindEq": "t1", "IfStale": "t2", "LoopStale": "t2",
}

func TestN064_FoldOnDoesNotUseAStaleConstant(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", "n064-collision-anf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Probes []struct {
			Name        string          `json:"name"`
			Source      string          `json:"source"`
			IR          json.RawMessage `json:"ir"`
			FoldOff     string          `json:"foldOff"`
			StaleFoldOn string          `json:"staleFoldOn"`
		} `json:"probes"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Probes) != 4 {
		t.Fatalf("want 4 probes, got %d", len(corpus.Probes))
	}
	for _, pr := range corpus.Probes {
		t.Run(pr.Name, func(t *testing.T) {
			// N-065: the source form is refused.
			want := ir.ReservedNameMessage(n064CollidingLocal[pr.Name])
			r := CompileFromSourceStrWithResult(pr.Source, pr.Name+".runar.ts")
			refused := false
			for _, d := range r.Diagnostics {
				if d.Message == want {
					refused = true
				}
			}
			if r.Success || !refused {
				t.Fatalf("source not refused with %q: %v", want, r.Diagnostics)
			}

			if pr.FoldOff == pr.StaleFoldOn {
				t.Fatal("corpus: foldOff equals staleFoldOn")
			}
			for _, disableFold := range []bool{true, false} {
				program, err := ir.LoadIRFromBytes(pr.IR)
				if err != nil {
					t.Fatalf("load: %v", err)
				}
				art, err := CompileFromProgram(program, CompileOptions{DisableConstantFolding: disableFold})
				if err != nil {
					t.Fatalf("fold-off=%v: %v", disableFold, err)
				}
				if art.Script != pr.FoldOff {
					t.Errorf("fold-off=%v: want %s, got %s (stale fold gives %s)", disableFold, pr.FoldOff, art.Script, pr.StaleFoldOn)
				}
			}
		})
	}
}
