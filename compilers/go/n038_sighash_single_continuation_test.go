package main

// N-038 (R64): a stateful @sighash SINGLE|FORKID method's continuation hashes
// only the method's own output (BIP-143 SINGLE commits hashOutputs to
// hash256(output[inputIndex]) alone) and declares no _changePKH /
// _changeAmount. Proves the Go tier's fold-OFF IR and script for the
// N-038 contract are byte-identical to the TS-stamped sdk-call pins
// and that bump's ABI params are exactly [txPreimage] while it stays
// non-terminal; reset (default ALL|FORKID) keeps its change params.
// Does not prove on-chain acceptance — that is the sdk-call vector Spend
// replay (conformance/sdk-call/sdk-call.test.ts).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
)

func TestN038SighashSingleContinuation(t *testing.T) {
	src := filepath.Join("..", "..", "conformance", "sdk-call", "SingleCounter.runar.ts")
	fixture := filepath.Join("..", "..", "conformance", "sdk-call")
	opts := compiler.CompileOptions{DisableConstantFolding: true}

	program, err := compiler.CompileSourceToIR(src, opts)
	if err != nil {
		t.Fatalf("compile IR: %v", err)
	}
	rawIR, err := json.MarshalIndent(program, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	gotIR, err := canonicalizeJSON(rawIR)
	if err != nil {
		t.Fatal(err)
	}
	wantRaw, err := os.ReadFile(filepath.Join(fixture, "expected-ir.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantIR, err := canonicalizeJSON(wantRaw)
	if err != nil {
		t.Fatal(err)
	}
	if gotIR != wantIR {
		t.Errorf("IR differs from the golden:\n%s", shortDiff(wantIR, gotIR))
	}

	artifact, err := compiler.CompileFromSource(src, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	wantHexRaw, err := os.ReadFile(filepath.Join(fixture, "expected-script.hex"))
	if err != nil {
		t.Fatal(err)
	}
	wantHex := strings.ToLower(strings.Join(strings.Fields(string(wantHexRaw)), ""))
	if artifact.Script != wantHex {
		t.Errorf("script differs from the golden: got %d hex chars, want %d", len(artifact.Script), len(wantHex))
	}

	for _, m := range artifact.ABI.Methods {
		var names []string
		for _, p := range m.Params {
			names = append(names, p.Name)
		}
		switch m.Name {
		case "bump":
			if strings.Join(names, ",") != "txPreimage" {
				t.Errorf("bump params = %v, want [txPreimage]", names)
			}
			if m.IsTerminal != nil && *m.IsTerminal {
				t.Errorf("bump must stay non-terminal")
			}
		case "reset":
			if strings.Join(names, ",") != "_changePKH,_changeAmount,_newAmount,txPreimage" {
				t.Errorf("reset params = %v", names)
			}
		}
	}
}
