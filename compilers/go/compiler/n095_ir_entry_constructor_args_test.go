package compiler

// N-095: the IR / direct-program entry points bake and validate
// ConstructorArgs exactly as the source pipeline does (TS compileFromANF,
// Rust F-103).
//
// Proves: HashLock compiled through CompileFromIR, CompileFromIRBytes and
// CompileFromProgram with {hashValue: <32 bytes>} is byte-identical to the
// source compile with the same args and carries no constructor slot; an
// unknown key, a width mismatch and an unbaked referenced readonly property
// are refused on every entry point; without args the slotted artifact is
// unchanged.
// Does not prove: the --ir JSON loader's own validation, or the CLI (it has no
// constructor-args flag). This is a pin: the Go tier already behaved this way
// (applyConstructorArgs in CompileFromProgram), so the test passes on base.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

func TestN095_IREntryPointsBakeAndValidateConstructorArgs(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "HashLock.runar.ts")
	if err := os.WriteFile(srcPath, []byte(hashLockSource), 0o644); err != nil {
		t.Fatal(err)
	}
	noFold := CompileOptions{DisableConstantFolding: true}
	program, err := CompileSourceToIR(srcPath, noFold)
	if err != nil {
		t.Fatalf("emit-ir: %v", err)
	}
	irJSON, err := json.Marshal(program)
	if err != nil {
		t.Fatal(err)
	}
	irPath := filepath.Join(dir, "HashLock.ir.json")
	if err := os.WriteFile(irPath, irJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	withArgs := func(args map[string]interface{}) CompileOptions {
		return CompileOptions{DisableConstantFolding: true, ConstructorArgs: args}
	}
	entries := map[string]func(args map[string]interface{}) (*Artifact, error){
		"CompileFromIR": func(a map[string]interface{}) (*Artifact, error) {
			return CompileFromIR(irPath, withArgs(a))
		},
		"CompileFromIRBytes": func(a map[string]interface{}) (*Artifact, error) {
			return CompileFromIRBytes(irJSON, withArgs(a))
		},
		"CompileFromProgram": func(a map[string]interface{}) (*Artifact, error) {
			p, err := ir.LoadIRFromBytes(irJSON)
			if err != nil {
				t.Fatal(err)
			}
			return CompileFromProgram(p, withArgs(a))
		},
	}

	expected, err := CompileFromSource(srcPath, withArgs(map[string]interface{}{"hashValue": hashHex}))
	if err != nil {
		t.Fatalf("source compile: %v", err)
	}

	for name, run := range entries {
		t.Run(name, func(t *testing.T) {
			got, err := run(map[string]interface{}{"hashValue": hashHex})
			if err != nil {
				t.Fatalf("bake: %v", err)
			}
			if got.Script != expected.Script {
				t.Errorf("IR entry script differs from source compile:\n got %s\nwant %s", got.Script, expected.Script)
			}
			if !strings.Contains(got.Script, hashHex) || len(got.ConstructorSlots) != 0 {
				t.Errorf("hash not baked (slots=%d)", len(got.ConstructorSlots))
			}

			for label, c := range map[string]struct {
				args map[string]interface{}
				want string
			}{
				"unknown key": {map[string]interface{}{"hashVal": hashHex}, "hashVal"},
				"wrong width": {map[string]interface{}{"hashValue": "aabb"}, "hashValue"},
				"unbaked":     {map[string]interface{}{"other": hashHex}, "other"},
			} {
				if _, err := run(c.args); err == nil || !strings.Contains(err.Error(), c.want) {
					t.Errorf("%s: expected a refusal naming %q, got %v", label, c.want, err)
				}
			}

			plain, err := run(nil)
			if err != nil {
				t.Fatalf("no-args compile: %v", err)
			}
			if len(plain.ConstructorSlots) != 1 || strings.Contains(plain.Script, hashHex) {
				t.Errorf("no-args compile must keep one placeholder slot; slots=%d", len(plain.ConstructorSlots))
			}
		})
	}
}
