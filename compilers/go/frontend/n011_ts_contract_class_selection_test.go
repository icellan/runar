package frontend

// N-011 — which class in a .runar.ts file is the contract.
//
// The TS reference (packages/runar-compiler/src/passes/01-parse.ts) walks
// EVERY class and keeps only one whose `extends` expression is exactly a valid
// base (SmartContract / StatefulSmartContract / UnsafeSmartContract):
//   - other classes are ignored wherever they sit;
//   - several valid classes -> "Only one SmartContract subclass is allowed per
//     file" at each valid class after the first (the LAST one is kept);
//   - no valid class -> "No class extending SmartContract,
//     StatefulSmartContract, or UnsafeSmartContract found" at 1:0.
//
// The Go tier already selected the right class on the seven F-016 shapes, but
// worded both diagnostics differently from TS and attached no location. It
// also matched the base by SUBSTRING of the heritage text, so a lone
// `class Helper extends NotSmartContract` compiled as a SmartContract where TS
// refuses it.
//
// Expected values were captured by running the TS reference on the same
// shapes. What this proves: the Go .runar.ts parser picks the same class and
// emits the same diagnostics (message + line:column) as the TS reference on
// the seven F-016 shapes plus the substring-base shape. What it does NOT
// prove: the other Go-tier surfaces (.runar.go selection is F-010's test).

import (
	"strings"
	"testing"
)

const (
	n011NoClass = "No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found"
	n011OnlyOne = "Only one SmartContract subclass is allowed per file"
	n011Imports = "import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';\n\n"
	n011Hash    = `export class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
`
	n011Decoy = `class Helper {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) !== this.hashValue);
  }
}
`
	n011Three = `import { SmartContract, assert } from 'runar-lang';

export class A extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 1n); }
}
export class B extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 2n); }
}
export class C extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 3n); }
}
`
)

func n011Foreign(base string) string {
	return strings.Replace(n011Decoy, "class Helper {", "class Helper extends "+base+" {", 1)
}

var n011TwoValid = n011Imports + `export class First extends SmartContract {
  constructor() {
    super();
  }

  public unlock(preimage: ByteString) {
    assert(true);
  }
}
` + "\n" + n011Hash

type n011Diag struct {
	msg          string
	line, column int
}

func n011Diags(r *ParseResult) []n011Diag {
	var out []n011Diag
	for _, e := range r.Errors {
		d := n011Diag{msg: e.Message}
		if e.Loc != nil {
			d.line, d.column = e.Loc.Line, e.Loc.Column
		}
		out = append(out, d)
	}
	return out
}

func TestN011_TsContractClassSelection(t *testing.T) {
	selects := []struct{ name, src string }{
		{"DECOY_FIRST", n011Imports + n011Decoy + "\n" + n011Hash},
		{"FOREIGN_BASE_FIRST", n011Imports + n011Foreign("Base") + "\n" + n011Hash},
		{"CONTRACT_FIRST", n011Imports + n011Hash + "\n" + n011Decoy},
	}
	for _, c := range selects {
		t.Run(c.name, func(t *testing.T) {
			r := ParseSource([]byte(c.src), "Probe.runar.ts")
			if len(r.Errors) != 0 {
				t.Fatalf("unexpected errors: %v", n011Diags(r))
			}
			if r.Contract == nil || r.Contract.Name != "HashLock" || r.Contract.ParentClass != "SmartContract" {
				t.Fatalf("selected %+v, want HashLock extends SmartContract", r.Contract)
			}
		})
	}

	refuses := []struct {
		name, src string
		want      []n011Diag
		keep      string
	}{
		{"NO_EXTENDS_ONLY", n011Imports + n011Decoy, []n011Diag{{n011NoClass, 1, 0}}, ""},
		{"FOREIGN_BASE_ONLY", n011Imports + n011Foreign("Base"), []n011Diag{{n011NoClass, 1, 0}}, ""},
		{"SUBSTRING_BASE_ONLY", n011Imports + n011Foreign("NotSmartContract"), []n011Diag{{n011NoClass, 1, 0}}, ""},
		{"TWO_VALID", n011TwoValid, []n011Diag{{n011OnlyOne, 13, 0}}, "HashLock"},
		{"THREE_VALID", n011Three, []n011Diag{{n011OnlyOne, 7, 0}, {n011OnlyOne, 11, 0}}, "C"},
	}
	for _, c := range refuses {
		t.Run(c.name, func(t *testing.T) {
			r := ParseSource([]byte(c.src), "Probe.runar.ts")
			got := n011Diags(r)
			if len(got) != len(c.want) {
				t.Fatalf("diagnostics = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("diagnostic %d = %v, want %v", i, got[i], c.want[i])
				}
			}
			if c.keep == "" {
				if r.Contract != nil {
					t.Fatalf("contract %q returned, want none", r.Contract.Name)
				}
			} else if r.Contract == nil || r.Contract.Name != c.keep {
				t.Fatalf("contract = %+v, want %s", r.Contract, c.keep)
			}
		})
	}
}
