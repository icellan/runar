package compiler

import (
	"strings"
	"testing"
)

// N-002 (CL-BUG-214, the cross-tier half of F-013): an index assignment is
// only a write when its root is a FixedArray contract property.
//
// ExpandFixedArrays rewrites `c.Arr[i] = v` only when Arr is a FixedArray
// property. Every other index target (a ByteString property, a local, a
// parameter, a member-chained root) survived to ANF lowering, which lowered it
// as a READ and dropped the value: a deployable script, no diagnostic, state
// that never changes. Pre-fix, F-013's Blob.runar.ts compiled here to the same
// `61ab7676aa517f…` script as TS/Rust/Zig, which @bsv/sdk Spend.validate
// showed accepting a continuation with the UNCHANGED blob (remediation-logs/
// N-002/exec-proof*.txt).
//
// What this proves: the Go tier refuses every non-FixedArray index-write shape
// below with F-013's shared diagnostic and a location, on the TS surface and on
// the Go surface, and still compiles FixedArray index writes (literal,
// runtime, compound, ++, nested literal).
// What this does not prove: the other tiers (their own suites and
// conformance/negatives/N81-N94 cover that), or byte-identity of the
// FixedArray goldens (the conformance golden + multi-format runs do).

const n002Needle = "index assignment is only supported on FixedArray contract properties; " +
	"the target here is not a FixedArray property"

func n002Blob(body string) string {
	return `import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class Blob extends StatefulSmartContract {
  blob: ByteString;

  constructor(blob: ByteString) {
    super(blob);
    this.blob = blob;
  }

  public poke(i: bigint) {
    ` + body + `
    assert(true);
  }
}
`
}

const n002TsLocal = `import { SmartContract, ByteString, assert } from 'runar-lang';

class Loc extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public unlock(b: ByteString) {
    let c: ByteString = b;
    c[0n] = 7n;
    assert(c == this.h);
  }
}
`

const n002TsParam = `import { SmartContract, ByteString, assert } from 'runar-lang';

class Par extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public unlock(b: ByteString) {
    b[0n] = 7n;
    assert(b == this.h);
  }
}
`

const n002GoProp = `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Blob struct {
	runar.StatefulSmartContract
	Blob runar.ByteString
}

func (c *Blob) Poke() {
	c.Blob[0] = 7
	runar.Assert(true)
}
`

const n002GoLocalParam = `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Loc struct {
	runar.SmartContract
	H runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *Loc) Unlock(b runar.ByteString) {
	d := b
	d[0] = 7
	b[1] = 7
	runar.Assert(d == c.H)
}
`

func n002ExpectRefused(t *testing.T, source, fileName string, want int) {
	t.Helper()
	r := CompileFromSourceStrWithResult(source, fileName)
	if r.Success || r.Artifact != nil {
		t.Fatalf("%s compiled a script that silently drops the write", fileName)
	}
	got := 0
	for _, d := range r.Diagnostics {
		if d.Message == n002Needle {
			got++
			if d.Loc == nil || d.Loc.Line <= 0 {
				t.Errorf("%s: diagnostic carries no location: %+v", fileName, d)
			}
		}
	}
	if got != want {
		msgs := make([]string, 0, len(r.Diagnostics))
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("%s: expected %d %q diagnostic(s), got %d; diagnostics: %s", fileName, want, n002Needle, got, strings.Join(msgs, " | "))
	}
}

func TestN002_NonFixedArrayIndexAssignmentIsRefused(t *testing.T) {
	cases := []struct {
		name, fileName, source string
		want                   int
	}{
		{"ts/bytestring-prop-literal", "Blob.runar.ts", n002Blob("this.blob[0n] = 7n;"), 1},
		{"ts/bytestring-prop-runtime", "Blob.runar.ts", n002Blob("this.blob[i] = 7n;"), 1},
		{"ts/bytestring-prop-plus-eq", "Blob.runar.ts", n002Blob("this.blob[0n] += 7n;"), 1},
		{"ts/bytestring-prop-minus-eq", "Blob.runar.ts", n002Blob("this.blob[0n] -= 7n;"), 1},
		{"ts/bytestring-prop-mul-eq", "Blob.runar.ts", n002Blob("this.blob[0n] *= 7n;"), 1},
		{"ts/bytestring-prop-div-eq", "Blob.runar.ts", n002Blob("this.blob[0n] /= 7n;"), 1},
		{"ts/bytestring-prop-mod-eq", "Blob.runar.ts", n002Blob("this.blob[0n] %= 7n;"), 1},
		{"ts/bytestring-prop-nested", "Blob.runar.ts", n002Blob("this.blob[0n][1n] = 7n;"), 1},
		{"ts/member-chained-root", "Blob.runar.ts", n002Blob("this.blob.x[0n] = 7n;"), 1},
		{"ts/local", "Loc.runar.ts", n002TsLocal, 1},
		{"ts/param", "Par.runar.ts", n002TsParam, 1},
		{"go/bytestring-prop", "Blob.runar.go", n002GoProp, 1},
		{"go/local+param", "Loc.runar.go", n002GoLocalParam, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { n002ExpectRefused(t, c.source, c.fileName, c.want) })
	}
}

const n002FixedArrayWrites = `import { StatefulSmartContract, FixedArray, assert } from 'runar-lang';

class Board extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public set(i: bigint, v: bigint) {
    this.board[i] = v;
    this.board[0n] = v;
    this.board[1n] += v;
    this.board[2n]++;
    this.grid[0n][1n] = v;
    assert(true);
  }
}
`

func TestN002_FixedArrayIndexAssignmentStillCompiles(t *testing.T) {
	r := CompileFromSourceStrWithResult(n002FixedArrayWrites, "Board.runar.ts")
	if !r.Success || r.Artifact == nil {
		msgs := []string{}
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("FixedArray index writes must compile; diagnostics: %s", strings.Join(msgs, " | "))
	}
}
