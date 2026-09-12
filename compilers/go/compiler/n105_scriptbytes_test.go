package compiler

// N-105 (1/2) — a NUMBER in the scriptBytes position of addRawOutput /
// addDataOutput.
//
// Same shape as N-098, one argument slot over, and the slot is the created
// output's LOCKING SCRIPT.
//
// This tier ACCEPTED `this.addRawOutput(1000n, n)` with `n: bigint`, and the
// emitted script was byte-identical to the same contract written with
// `n: ByteString` — measured through this compiler, same digest. So the
// operand is not converted: whatever sits in that slot is spliced into the
// output serialization as the output's script.
//
// `lowerAddRawOutput` takes OP_SIZE of the operand, varint-prefixes it, and
// concatenates it after the 8-byte amount. A script NUMBER on the stack is its
// minimal little-endian encoding, so the covenant ends up committing to an
// output whose locking script is those bytes. Executed on the real @bsv/sdk
// Spend engine, against the exact 55-opcode window all six tiers emit:
//
//	n=0     -> scriptLen 0   locking script (empty)     — anyone-can-spend
//	n=81    -> scriptLen 1   0x51 = OP_1                — anyone-can-spend
//	n=118   -> scriptLen 1   0x76 = OP_DUP              — anyone-can-spend
//	n=1000  -> scriptLen 2   0xe8 0x03, 0xe8 invalid    — unspendable
//
// N-098's failure mode was a wrong amount or a frozen UTXO. This one can hand
// the whole output to anybody who sees it, which is why it is a gate.
//
// The rule ported here is the TypeScript reference's, wording included:
// checkCallExpr's addRawOutput / addDataOutput arms in
// packages/runar-compiler/src/passes/03-typecheck.ts.
//
// `<unknown>` stays ACCEPTED, exactly as TS has it — a private helper's
// declared return type is discarded at parse time in every tier.

import (
	"strings"
	"testing"
)

const n105ScriptBytesHead = `import { StatefulSmartContract, ByteString, Ripemd160, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly base: bigint;
  readonly flag: boolean;
  readonly blob: ByteString;
  readonly pkh: Ripemd160;

  constructor(count: bigint, base: bigint, flag: boolean, blob: ByteString, pkh: Ripemd160) {
    super(count, base, flag, blob, pkh);
    this.count = count;
    this.base = base;
    this.flag = flag;
    this.blob = blob;
    this.pkh = pkh;
  }

  private bytes(): ByteString { return this.blob; }

`

func n105ScriptBytesContract(body string) string {
	return n105ScriptBytesHead + body + "}\n"
}

// --- REJECT ----------------------------------------------------------------

var n105RawBigintScript = n105ScriptBytesContract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.base);
  }
`)

var n105DataBigintScript = n105ScriptBytesContract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(500n, this.base);
  }
`)

var n105RawBooleanScript = n105ScriptBytesContract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.flag);
  }
`)

// --- ACCEPT (over-rejection guards) ----------------------------------------

var n105RawByteStringScript = n105ScriptBytesContract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.blob);
  }
`)

var n105RawStateScript = n105ScriptBytesContract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.getStateScript());
  }
`)

// A ByteString SUBTYPE. TS's rule is isSubtype(scriptType, 'ByteString'), not
// equality, so Ripemd160 must keep compiling.
var n105RawSubtypeScript = n105ScriptBytesContract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.pkh);
  }
`)

// A private helper's declared return type is discarded at parse time in every
// tier, so this infers as <unknown>. TS escapes it; every port must too.
var n105RawHelperScript = n105ScriptBytesContract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.bytes());
  }
`)

var n105DataByteStringScript = n105ScriptBytesContract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(500n, this.blob);
  }
`)

// ---------------------------------------------------------------------------

func TestN105_AddRawOutputRejectsBigintScriptBytes(t *testing.T) {
	n098RequireDiagnostic(t, n105RawBigintScript,
		"addRawOutput() second argument (scriptBytes) must be ByteString, got 'bigint'")
}

func TestN105_AddDataOutputRejectsBigintScriptBytes(t *testing.T) {
	n098RequireDiagnostic(t, n105DataBigintScript,
		"addDataOutput() second argument (scriptBytes) must be ByteString, got 'bigint'")
}

func TestN105_AddRawOutputRejectsBooleanScriptBytes(t *testing.T) {
	n098RequireDiagnostic(t, n105RawBooleanScript,
		"addRawOutput() second argument (scriptBytes) must be ByteString, got 'boolean'")
}

func TestN105_AcceptedScriptBytesPositions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"ByteString property", n105RawByteStringScript},
		{"getStateScript()", n105RawStateScript},
		{"ByteString subtype (Ripemd160)", n105RawSubtypeScript},
		{"private helper call, inferred as <unknown>", n105RawHelperScript},
		{"addDataOutput with a ByteString property", n105DataByteStringScript},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if hex := n098Hex(t, tc.source); hex == "" {
				t.Fatalf("compiled to an empty script")
			}
		})
	}
}

// Non-vacuity: "it compiled" would also hold for a tier that discarded the
// scriptBytes operand. Two DIFFERENT ByteString operands must lower to
// different scripts.
func TestN105_ScriptBytesOperandReachesCodegen(t *testing.T) {
	a := n098Hex(t, n105RawByteStringScript)
	b := n098Hex(t, n105RawStateScript)
	if a == b {
		t.Fatalf("two different scriptBytes operands produced the same script — the operand is being dropped")
	}
}

// The reason this was invisible: the rejected source lowered EXACTLY like a
// correct one. Pin that the ByteString-typed twin still compiles, so the rule
// removes the bad program and nothing else.
func TestN105_ByteStringTwinStillCompiles(t *testing.T) {
	if !strings.Contains(strings.Join(n098Errors(t, n105RawBigintScript), "\n"), "scriptBytes") {
		t.Fatalf("the bigint-scriptBytes source was not rejected")
	}
	if errs := n098Errors(t, n105RawByteStringScript); len(errs) != 0 {
		t.Fatalf("the ByteString twin must still compile; got %v", errs)
	}
}
