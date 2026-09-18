package compiler

// N-098 — a ByteString in the SATOSHIS position of an output intrinsic.
//
// This tier ACCEPTED all three shapes. It was not a missing diagnostic: the
// ByteString was lowered into the satoshis slot with NO conversion, and the
// emitted script was byte-identical to the same contract written with
// `blob: bigint` — both 1358 hexchars, same digest, measured through this
// compiler.
//
// lowerAddOutput prepends the satoshis operand as `OP_8 OP_NUM2BIN`, so the
// covenant commits to whatever those bytes decode to as a script number.
// Executed on the real @bsv/sdk Spend engine with `blob = 0x2a`, a 42-satoshi
// continuation VALIDATES and the 1000-satoshi one the author funded is
// REJECTED. Larger blobs fail shut, not safe: 0xcafebabefeed0001 demands
// 7.2e16 satoshis and a 20-byte hash aborts the script at OP_NUM2BIN, leaving
// the UTXO permanently unspendable.
//
// The rule ported here is the TypeScript reference's, wording included:
// checkCallExpr's addOutput / addRawOutput / addDataOutput arms in
// packages/runar-compiler/src/passes/03-typecheck.ts. Only the FIRST argument
// is checked. TS additionally checks arity, the state-value types and
// addRawOutput/addDataOutput's scriptBytes argument; none of those are ported
// here and none of them are this finding — deliberately out of scope, and
// flagged rather than bundled.
//
// The ACCEPT block carries the real risk in a change like this. `<unknown>`
// must stay accepted: a private helper's declared return type is discarded at
// parse time in every tier, so `this.sats()` infers as `<unknown>`, and TS has
// always escaped it here.

import (
	"strings"
	"testing"
)

const n098Head = `import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, base: bigint, blob: ByteString) {
    super(count, base, blob);
    this.count = count;
    this.base = base;
    this.blob = blob;
  }

  private sats(): bigint { return this.base; }

`

func n098Contract(body string) string {
	return n098Head + body + "}\n"
}

// --- REJECT ----------------------------------------------------------------

var n098AddOutput = n098Contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.blob, this.count);
  }
`)

var n098AddRawOutput = n098Contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(this.blob, this.blob);
  }
`)

var n098AddDataOutput = n098Contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(this.blob, this.blob);
  }
`)

// --- ACCEPT (over-rejection guards) ----------------------------------------

var n098LiteralSats = n098Contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
  }
`)

var n098ParamSats = n098Contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(n, this.count);
  }
`)

var n098PropertySats = n098Contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.base, this.count);
  }
`)

var n098HelperSats = n098Contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.sats(), this.count);
  }
`)

// ---------------------------------------------------------------------------

func n098Errors(t *testing.T, source string) []string {
	t.Helper()
	res := CompileFromSourceStrWithResult(source, "C.runar.ts")
	var out []string
	for _, d := range res.Diagnostics {
		if d.Severity == "error" {
			out = append(out, d.FormatMessage())
		}
	}
	return out
}

func n098RequireDiagnostic(t *testing.T, source, want string) {
	t.Helper()
	errs := n098Errors(t, source)
	for _, e := range errs {
		if strings.Contains(e, want) {
			return
		}
	}
	t.Fatalf("expected a diagnostic containing %q; got %v", want, errs)
}

func n098Hex(t *testing.T, source string) string {
	t.Helper()
	res := CompileFromSourceStrWithResult(source, "C.runar.ts")
	if !res.Success {
		t.Fatalf("expected this contract to compile; diagnostics: %v", n098Errors(t, source))
	}
	return res.ScriptHex
}

func TestN098_AddOutputRejectsByteStringSatoshis(t *testing.T) {
	n098RequireDiagnostic(t, n098AddOutput,
		"addOutput() first argument (satoshis) must be bigint, got 'ByteString'")
}

func TestN098_AddRawOutputRejectsByteStringSatoshis(t *testing.T) {
	n098RequireDiagnostic(t, n098AddRawOutput,
		"addRawOutput() first argument (satoshis) must be bigint, got 'ByteString'")
}

func TestN098_AddDataOutputRejectsByteStringSatoshis(t *testing.T) {
	n098RequireDiagnostic(t, n098AddDataOutput,
		"addDataOutput() first argument (satoshis) must be bigint, got 'ByteString'")
}

func TestN098_AcceptedSatoshisPositions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"bigint literal", n098LiteralSats},
		{"bigint method parameter", n098ParamSats},
		{"bigint contract property", n098PropertySats},
		{"private helper call, inferred as <unknown>", n098HelperSats},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if hex := n098Hex(t, tc.source); hex == "" {
				t.Fatalf("compiled to an empty script")
			}
		})
	}
}

// Non-vacuity: "it compiled" would also hold for a tier that discarded the
// satoshis operand entirely. A literal and a runtime parameter must lower to
// DIFFERENT scripts. Every tier's own N-098 test makes this same assertion.
func TestN098_SatoshisOperandReachesCodegen(t *testing.T) {
	lit := n098Hex(t, n098LiteralSats)
	param := n098Hex(t, n098ParamSats)
	if lit == param {
		t.Fatalf("literal and parameter satoshis produced the same script — the operand is being dropped")
	}
	if !strings.Contains(lit, "02e803") { // PUSH(2) 0xe8 0x03 == 1000
		t.Fatalf("literal 1000n does not appear in the emitted script")
	}
}
