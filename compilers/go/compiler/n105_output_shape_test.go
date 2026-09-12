package compiler

// N-105 (2/2) — the rest of TypeScript's output-intrinsic CONTRACT: the
// StatefulSmartContract gate, the arity of all three intrinsics, and the types
// of addOutput's state values.
//
// N-098 ported the satoshis check and N-105 (1/2) the scriptBytes check. These
// three are the remainder, and each one is a hole with an executed consequence
// in this tier:
//
//   this.addOutput(1000n)                      1352 hexchars — the state value
//     with one mutable property                is simply MISSING from the
//                                              continuation; the correct call
//                                              emits 1362.
//   this.addOutput(1000n, this.count, 5n)      1368 hexchars — the surplus
//                                              value is appended to the state
//                                              serialization the next spend
//                                              will deserialize by fixed
//                                              offsets.
//   this.addOutput(1000n, this.blob)           1362 hexchars, DIFFERENT bytes
//     with count: bigint                       from the correct call — the
//                                              ByteString is serialized where
//                                              an 8-byte LE number belongs.
//   this.addRawOutput(...) in a stateless      152 hexchars — a "continuation"
//     SmartContract                            in a contract that has no state.
//
// All four are the same class as N-098: the compiler does not refuse, it emits
// a covenant that commits to the wrong thing.
//
// Ported from the TypeScript reference (checkCallExpr's addOutput /
// addRawOutput / addDataOutput arms in
// packages/runar-compiler/src/passes/03-typecheck.ts), wording included.
//
// The ACCEPT block is where the risk is. In particular a ByteString-typed value
// in a PubKey-typed state slot must stay ACCEPTED: TS's isSubtype treats the
// ByteString family as bidirectionally compatible, and this tier's general
// isSubtype does not, so the state-value check uses TS's rule rather than this
// tier's. See outputStateValueMatches.

import (
	"testing"
)

const n105ShapeHead = `import { StatefulSmartContract, ByteString, PubKey, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  owner: PubKey;
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, owner: PubKey, base: bigint, blob: ByteString) {
    super(count, owner, base, blob);
    this.count = count;
    this.owner = owner;
    this.base = base;
    this.blob = blob;
  }

  private anything(): bigint { return this.base; }

`

func n105ShapeContract(body string) string {
	return n105ShapeHead + body + "}\n"
}

const n105StatelessHead = `import { SmartContract, ByteString, assert } from 'runar-lang';

class C extends SmartContract {
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(base: bigint, blob: ByteString) {
    super(base, blob);
    this.base = base;
    this.blob = blob;
  }

`

func n105StatelessContract(body string) string {
	return n105StatelessHead + body + "}\n"
}

// --- REJECT: arity --------------------------------------------------------

var n105ArityTooFew = n105ShapeContract(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count);
  }
`)

var n105ArityTooMany = n105ShapeContract(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner, 5n);
  }
`)

var n105RawArityOne = n105ShapeContract(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addRawOutput(500n);
  }
`)

var n105RawArityThree = n105ShapeContract(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addRawOutput(500n, this.blob, 7n);
  }
`)

var n105DataArityThree = n105ShapeContract(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addDataOutput(500n, this.blob, 7n);
  }
`)

// --- REJECT: state-value types --------------------------------------------

var n105StateValueWrongType = n105ShapeContract(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.blob, this.owner);
  }
`)

// --- REJECT: the StatefulSmartContract gate -------------------------------

var n105StatelessAddOutput = n105StatelessContract(`  public m(n: bigint) {
    this.addOutput(1000n, n);
    assert(n > 0n);
  }
`)

var n105StatelessAddRawOutput = n105StatelessContract(`  public m(n: bigint) {
    this.addRawOutput(1000n, this.blob);
    assert(n > 0n);
  }
`)

var n105StatelessAddDataOutput = n105StatelessContract(`  public m(n: bigint) {
    this.addDataOutput(1000n, this.blob);
    assert(n > 0n);
  }
`)

// --- ACCEPT (over-rejection guards) ---------------------------------------

var n105ShapeExact = n105ShapeContract(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
  }
`)

// A ByteString value in a PubKey state slot. TS's isSubtype treats the
// ByteString family as bidirectionally compatible, so TS ACCEPTS this and every
// tier must keep accepting it — measured before this change: all seven tiers
// compiled it to the same script.
var n105ShapeFamilyWidening = n105ShapeContract(`  public m(n: bigint, b: ByteString) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count, b);
  }
`)

// A private helper's declared return type is discarded at parse time in every
// tier, so this infers as <unknown>. TS escapes it; every port must too.
var n105ShapeUnknownStateValue = n105ShapeContract(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.anything(), this.owner);
  }
`)

// A FixedArray state property. ExpandFixedArrays runs AFTER the typechecker in
// this tier and splits `board` into three scalar siblings, so the only call
// shape that lowers is the EXPANDED one below — which the arity rule, counting
// the two DECLARED mutable properties, would reject. This is the contract from
// compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py,
// checked into this repo and compiled by all six non-TS tiers; the TypeScript
// reference rejects it ("expects 3 argument(s) ... got 5"), which is a defect in
// the reference rule, not in this source. The arity and state-value checks are
// scoped out of contracts with FixedArray state for exactly this reason.
var n105FixedArrayState = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n); }
}
`

// ---------------------------------------------------------------------------

func TestN105_FixedArrayStateIsOutOfScope(t *testing.T) {
	res := CompileFromSourceStrWithResult(n105FixedArrayState, "Boardy.runar.ts")
	if !res.Success {
		var errs []string
		for _, d := range res.Diagnostics {
			if d.Severity == "error" {
				errs = append(errs, d.FormatMessage())
			}
		}
		t.Fatalf("a FixedArray-state contract must stay compilable; got %v", errs)
	}
}

func TestN105_AddOutputArity(t *testing.T) {
	n098RequireDiagnostic(t, n105ArityTooFew,
		"addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 2")
	n098RequireDiagnostic(t, n105ArityTooMany,
		"addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 4")
}

func TestN105_RawAndDataOutputArity(t *testing.T) {
	n098RequireDiagnostic(t, n105RawArityOne,
		"addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 1")
	n098RequireDiagnostic(t, n105RawArityThree,
		"addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 3")
	n098RequireDiagnostic(t, n105DataArityThree,
		"addDataOutput() expects 2 arguments (satoshis, scriptBytes), got 3")
}

func TestN105_AddOutputStateValueTypes(t *testing.T) {
	n098RequireDiagnostic(t, n105StateValueWrongType,
		"addOutput() argument 2 (count) must be 'bigint', got 'ByteString'")
}

func TestN105_OutputIntrinsicsAreStatefulOnly(t *testing.T) {
	n098RequireDiagnostic(t, n105StatelessAddOutput,
		"addOutput() is only available in StatefulSmartContract")
	n098RequireDiagnostic(t, n105StatelessAddRawOutput,
		"addRawOutput() is only available in StatefulSmartContract")
	n098RequireDiagnostic(t, n105StatelessAddDataOutput,
		"addDataOutput() is only available in StatefulSmartContract")
}

func TestN105_AcceptedOutputShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"exact arity and exact types", n105ShapeExact},
		{"ByteString value in a PubKey state slot", n105ShapeFamilyWidening},
		{"private helper call, inferred as <unknown>", n105ShapeUnknownStateValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if hex := n098Hex(t, tc.source); hex == "" {
				t.Fatalf("compiled to an empty script")
			}
		})
	}
}

// Non-vacuity: the arity rule must be derived from the contract's mutable
// properties, not hardcoded. A two-mutable-property contract wants three
// arguments; the one-mutable-property head used by the N-105 scriptBytes tests
// wants two, and that source must still compile.
func TestN105_ArityIsDerivedFromMutableProperties(t *testing.T) {
	if hex := n098Hex(t, n105RawByteStringScript); hex == "" {
		t.Fatalf("a one-mutable-property addOutput(sats, value) stopped compiling")
	}
	if hex := n098Hex(t, n105ShapeExact); hex == "" {
		t.Fatalf("a two-mutable-property addOutput(sats, v1, v2) stopped compiling")
	}
}
