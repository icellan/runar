package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-038 / F-065 / F-066 / F-070 — `--emit-ir` -> `--ir` must reproduce the
// artifact's parentClass and abi.methods[].sigHashType.
//
// Both used to be `json:"-"` carriers on ANFProgram / ANFMethod, so an IR file
// written by `--emit-ir` and compiled by `--ir` produced the same script but an
// artifact with NO parentClass and NO sigHashType. The SDK signs by both: no
// parentClass on a StatefulSmartContract with zero mutable fields skips the
// issue-#44 subscript trim, and no sigHashType builds an ALL|FORKID preimage
// for a covenant that asserts another mode — both spends fail on chain.
//
// What this proves: in this tier, the JSON of the program --emit-ir prints
// carries both keys, CompileFromIRBytes on that JSON yields the same script,
// parentClass and abi as CompileFromSource, and the loader refuses a present
// but illegal value with the diagnostic shared by all seven tiers.
// What it does not prove: the other tiers (conformance/ir-roundtrip), or the
// SDK spend itself (same file, under @bsv/sdk Spend).

const f038ZeroMutable = `import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

class ZeroMutable extends StatefulSmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public claim(sig: Sig): void {
    assert(checkSig(sig, this.owner));
  }
}
`

const f038SighashCounter = `import { StatefulSmartContract, assert } from 'runar-lang';

class SighashCounter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  /** @sighash ALL|ANYONECANPAY|FORKID */
  public increment(): void {
    this.count = this.count + 1n;
    assert(true);
  }
}
`

const f038SighashSingle = `import { SmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

class SighashSingle extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  /** @sighash SINGLE|FORKID */
  public unlock(sig: Sig): void {
    assert(checkSig(sig, this.owner));
  }
}
`

func TestF038_EmitIRToIRKeepsParentClassAndSigHashType(t *testing.T) {
	cases := []struct {
		name, src, parent string
		sig               map[string]int
	}{
		{"ZeroMutable", f038ZeroMutable, "StatefulSmartContract", nil},
		{"SighashCounter", f038SighashCounter, "StatefulSmartContract", map[string]int{"increment": 0xc1}},
		{"SighashSingle", f038SighashSingle, "SmartContract", map[string]int{"unlock": 0x43}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.name+".runar.ts")
			if err := os.WriteFile(path, []byte(c.src), 0o644); err != nil {
				t.Fatal(err)
			}
			opts := CompileOptions{DisableConstantFolding: true}
			direct, err := CompileFromSource(path, opts)
			if err != nil {
				t.Fatalf("source compile: %v", err)
			}
			program, err := CompileSourceToIR(path, opts)
			if err != nil {
				t.Fatalf("emit-ir: %v", err)
			}
			irJSON, err := json.Marshal(program)
			if err != nil {
				t.Fatal(err)
			}

			// The wire JSON carries both keys.
			var wire struct {
				ParentClass string `json:"parentClass"`
				Methods     []struct {
					Name        string `json:"name"`
					SigHashType *int   `json:"sigHashType"`
				} `json:"methods"`
			}
			if err := json.Unmarshal(irJSON, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.ParentClass != c.parent {
				t.Errorf("emitted IR parentClass = %q, want %q", wire.ParentClass, c.parent)
			}
			for _, m := range wire.Methods {
				want, has := c.sig[m.Name]
				switch {
				case has && (m.SigHashType == nil || *m.SigHashType != want):
					t.Errorf("emitted IR method %s sigHashType = %v, want %d", m.Name, m.SigHashType, want)
				case !has && m.SigHashType != nil:
					t.Errorf("emitted IR method %s carries sigHashType %d, want none", m.Name, *m.SigHashType)
				}
			}

			viaIR, err := CompileFromIRBytes(irJSON, opts)
			if err != nil {
				t.Fatalf("--ir compile: %v", err)
			}
			if viaIR.Script != direct.Script {
				t.Errorf("script differs between --source and --ir")
			}
			if direct.ParentClass != c.parent {
				t.Errorf("direct parentClass = %q, want %q", direct.ParentClass, c.parent)
			}
			if viaIR.ParentClass != direct.ParentClass {
				t.Errorf("--ir parentClass = %q, --source parentClass = %q", viaIR.ParentClass, direct.ParentClass)
			}
			da, _ := json.Marshal(direct.ABI)
			va, _ := json.Marshal(viaIR.ABI)
			if string(da) != string(va) {
				t.Errorf("abi differs:\n--source %s\n--ir     %s", da, va)
			}
		})
	}
}

func TestF038_LoaderRefusesIllegalParentClassAndSigHashType(t *testing.T) {
	control := map[string]any{
		"contractName": "X",
		"properties":   []any{map[string]any{"name": "pk", "type": "PubKey", "readonly": true}},
		"methods": []any{map[string]any{
			"name": "unlock", "isPublic": true,
			"params": []any{map[string]any{"name": "sig", "type": "Sig"}},
			"body": []any{
				map[string]any{"name": "t0", "value": map[string]any{"kind": "load_param", "name": "sig"}},
				map[string]any{"name": "t1", "value": map[string]any{"kind": "load_prop", "name": "pk"}},
				map[string]any{"name": "t2", "value": map[string]any{"kind": "call", "func": "checkSig", "args": []any{"t0", "t1"}}},
				map[string]any{"name": "t3", "value": map[string]any{"kind": "assert", "value": "t2"}},
			},
		}},
	}
	with := func(top map[string]any, method map[string]any) []byte {
		raw, _ := json.Marshal(control)
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		for k, v := range top {
			doc[k] = v
		}
		m := doc["methods"].([]any)[0].(map[string]any)
		for k, v := range method {
			m[k] = v
		}
		out, _ := json.Marshal(doc)
		return out
	}

	// Controls: absent, legal values.
	for _, ok := range [][]byte{
		with(nil, nil),
		with(map[string]any{"parentClass": "SmartContract"}, map[string]any{"sigHashType": 0x43}),
	} {
		if _, err := CompileFromIRBytes(ok); err != nil {
			t.Fatalf("control refused: %v", err)
		}
	}

	bad := []struct {
		name string
		ir   []byte
		want string
	}{
		{"parent-class-number", with(map[string]any{"parentClass": 7}, nil),
			"IR validation: parentClass must be a string, got number"},
		{"parent-class-unknown", with(map[string]any{"parentClass": "Contract"}, nil),
			"IR validation: parentClass must be one of SmartContract, StatefulSmartContract, UnsafeSmartContract, got Contract"},
		{"sighash-type-string", with(nil, map[string]any{"sigHashType": "0x43"}),
			"IR validation: methods[0].sigHashType must be an integer, got string"},
		{"sighash-type-no-forkid", with(nil, map[string]any{"sigHashType": 3}),
			"IR validation: methods[0].sigHashType must be one of 65, 66, 67, 193, 194, 195, got 3"},
	}
	for _, b := range bad {
		t.Run(b.name, func(t *testing.T) {
			_, err := CompileFromIRBytes(b.ir)
			if err == nil {
				t.Fatalf("accepted")
			}
			if !strings.Contains(err.Error(), b.want) {
				t.Fatalf("got %q, want it to contain %q", err.Error(), b.want)
			}
		})
	}
}
