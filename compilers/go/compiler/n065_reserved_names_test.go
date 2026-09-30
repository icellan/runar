package compiler

// N-065 / N-060 — a user identifier spelled like a name the compiler mints is
// refused, with one diagnostic shared verbatim by all seven tiers
// (conformance/negatives/reserved-names-cases.json).
//
// Before: `let t2: bigint = p; assert(p > 0n); if (c) { t2 = p; }
// assert(t2 + 1n === 1n);` compiled (folding OFF) to a script that accepts
// p = 1, c = false, which the source rejects — `0n` lowers to the ANF temp t2
// and the final guard read the temp. `--ir` accepted parameters, properties,
// bindings and references named after stack lowering's own slots.
//
// Proves: every source case (all nine surfaces, after name mapping) is refused
// by the Go frontend with the shared sentence while its renamed twin compiles;
// a stateless contract's own txPreimage parameter compiles; every --ir case is
// refused by LoadIRFromBytes with the same sentence, and the accepted IR (ANF
// temps and __merge$ as binding names, txPreimage as a parameter) compiles to
// the P2PK control's bytes. Does not prove: the on-chain effect (the Spend
// oracle runs in conformance/negatives/reserved-names.test.ts).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

type n065Corpus struct {
	Source struct {
		Accept []struct {
			Name string `json:"name"`
			File string `json:"file"`
			Src  string `json:"src"`
		} `json:"accept"`
		Cases []struct {
			Name  string `json:"name"`
			File  string `json:"file"`
			Src   string `json:"src"`
			Twin  string `json:"twin"`
			Error string `json:"error"`
		} `json:"cases"`
	} `json:"source"`
	IR struct {
		Accept []struct {
			Name string          `json:"name"`
			IR   json.RawMessage `json:"ir"`
		} `json:"accept"`
		Cases []struct {
			Name  string          `json:"name"`
			IR    json.RawMessage `json:"ir"`
			Error string          `json:"error"`
		} `json:"cases"`
	} `json:"ir"`
}

func loadN065Corpus(t *testing.T) n065Corpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", "reserved-names-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c n065Corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Source.Cases) < 30 || len(c.IR.Cases) < 10 {
		t.Fatalf("corpus too small: %d source, %d ir", len(c.Source.Cases), len(c.IR.Cases))
	}
	return c
}

func TestN065_ReservedNamesInSource(t *testing.T) {
	c := loadN065Corpus(t)
	for _, tc := range c.Source.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			r := CompileFromSourceStrWithResult(tc.Src, tc.File, CompileOptions{DisableConstantFolding: true})
			if r.Success {
				t.Fatalf("accepted; want %q", tc.Error)
			}
			found := false
			var msgs []string
			for _, d := range r.Diagnostics {
				msgs = append(msgs, d.Message)
				if d.Message == tc.Error {
					found = true
				}
			}
			if !found {
				t.Fatalf("want diagnostic %q, got %q", tc.Error, msgs)
			}
			tw := CompileFromSourceStrWithResult(tc.Twin, tc.File, CompileOptions{DisableConstantFolding: true})
			if !tw.Success {
				t.Fatalf("renamed twin refused: %v", tw.Diagnostics)
			}
		})
	}
	for _, a := range c.Source.Accept {
		t.Run(a.Name, func(t *testing.T) {
			r := CompileFromSourceStrWithResult(a.Src, a.File)
			if !r.Success {
				t.Fatalf("refused: %v", r.Diagnostics)
			}
		})
	}
}

func TestN065_ReservedNamesInIR(t *testing.T) {
	c := loadN065Corpus(t)
	for _, tc := range c.IR.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := ir.LoadIRFromBytes(tc.IR)
			if err == nil {
				t.Fatalf("accepted; want %q", tc.Error)
			}
			if err.Error() != tc.Error {
				t.Fatalf("got  %q\nwant %q", err.Error(), tc.Error)
			}
		})
	}
	for _, a := range c.IR.Accept {
		t.Run(a.Name, func(t *testing.T) {
			art, err := CompileFromIRBytes(a.IR)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if art.Script != "00ac" {
				t.Fatalf("script %s, want 00ac", art.Script)
			}
		})
	}
}
