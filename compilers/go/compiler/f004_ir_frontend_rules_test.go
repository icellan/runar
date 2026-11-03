package compiler

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
)

// F-004 (CL-BUG-084 / CL-BUG-216 / CL-GAP-005) — the `--ir` entry point never
// runs frontend.Validate.
//
// CompileFromIR / CompileFromIRBytes / CompileFromProgram go straight from the
// loaded ANF to stack lowering. ir.ValidateIR is a STRUCTURAL check (known
// kinds, arities, loop bounds); none of frontend.Validate's semantic rules run.
// Two of those rules are the difference between a covenant and an
// anyone-can-spend output, and both are fully observable in the ANF:
//
//  1. "public method must end with an assert()". Stack lowering leaves the
//     LAST top-level binding's value as the script's result. A public method
//     whose body does not terminate in an assert (or an if whose arms both do,
//     or an UnsafeSmartContract terminal raw_script with out_arity 1) leaves
//     an arbitrary, spender-influenced value there.
//  2. "cannot assign to readonly property". A readonly property is a value
//     baked into the locking script. An update_prop on it in a spending method
//     shadows the baked value with whatever the method computed — typically a
//     witness value — so every later load_prop reads the spender's number.
//
// Each attack below is the hand-written IR of a source contract the source
// path refuses. The test asserts the IR path refuses it too; if it does not,
// it runs the emitted script under the go-sdk interpreter with a push-only
// unlocking script that knows no secret, to show what the refusal is worth.
//
// What this proves: the Go tier's CompileFromIRBytes (the function behind
// `runar-go --ir`) now refuses these two shapes, and — for the controls — still
// accepts the shapes the source pipeline legitimately produces (terminal
// if/else asserts, constructor-only property writes, mutable update_prop).
//
// What this does NOT prove: that every one of frontend.Validate's ~46 error
// sites is enforced on the IR path. Only the two rules above are ported to the
// ANF; the rest (recursion, sighash-usage matrix, txPreimage declarations,
// property-type rules, …) are either already covered by ir.ValidateIR / the
// R-012 SP1 guard, or remain source-only. It also says nothing about the other
// six tiers' --ir paths.

// noAssertIR is CL-BUG-216's NoAssert.runar.ts in ANF: `open(x) { const y = x + 0n; }`.
// Before the fix the Go tier compiled it to 0093 (OP_0 OP_ADD).
const noAssertIR = `{
	"contractName": "NoAssert",
	"properties": [],
	"methods": [{
		"name": "open",
		"isPublic": true,
		"params": [{"name": "x", "type": "bigint"}],
		"body": [
			{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t1", "value": {"kind": "load_const", "value": 0}},
			{"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}}
		]
	}]
}`

const noAssertSource = `import { SmartContract } from 'runar-lang';

class NoAssert extends SmartContract {
  constructor() { super(); }
  public open(x: bigint) {
    const y = x + 0n;
  }
}
`

// assertThenComputeIR asserts first and then computes a trailing value. The
// codegen marks the (earlier) assert terminal — no OP_VERIFY — and the
// trailing value becomes top-of-stack, so the assert is never enforced.
const assertThenComputeIR = `{
	"contractName": "AssertThenCompute",
	"properties": [{"name": "secret", "type": "bigint", "readonly": true, "initialValue": 42}],
	"methods": [{
		"name": "open",
		"isPublic": true,
		"params": [{"name": "x", "type": "bigint"}],
		"body": [
			{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t1", "value": {"kind": "load_prop", "name": "secret"}},
			{"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
			{"name": "t3", "value": {"kind": "assert", "value": "t2"}},
			{"name": "t4", "value": {"kind": "load_param", "name": "x"}}
		]
	}]
}`

// readonlyWriteIR is `unlock(x) { this.secret = x; assert(x === this.secret); }`
// on a readonly `secret` baked to 42.
const readonlyWriteIR = `{
	"contractName": "ReadonlyWrite",
	"properties": [{"name": "secret", "type": "bigint", "readonly": true, "initialValue": 42}],
	"methods": [{
		"name": "unlock",
		"isPublic": true,
		"params": [{"name": "x", "type": "bigint"}],
		"body": [
			{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t1", "value": {"kind": "update_prop", "name": "secret", "value": "t0"}},
			{"name": "t2", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t3", "value": {"kind": "load_prop", "name": "secret"}},
			{"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t2", "right": "t3"}},
			{"name": "t5", "value": {"kind": "assert", "value": "t4"}}
		]
	}]
}`

const readonlyWriteSource = `import { SmartContract, assert } from 'runar-lang';

class ReadonlyWrite extends SmartContract {
  readonly secret: bigint = 42n;
  constructor() { super(); }
  public unlock(x: bigint) {
    this.secret = x;
    assert(x === this.secret);
  }
}
`

// showSpendableWith compiles-succeeded diagnostics: runs the emitted locking
// script with the given push-only unlocking script and reports the outcome.
func showSpendableWith(t *testing.T, scriptHex string, unlocking []byte) string {
	t.Helper()
	lock, err := script.NewFromHex(scriptHex)
	if err != nil {
		return "unparseable script: " + err.Error()
	}
	if err := runSpend(lock, unlocking); err != nil {
		return "spend with unlocking " + hex.EncodeToString(unlocking) + " rejected: " + err.Error()
	}
	return "SPENDABLE by unlocking " + hex.EncodeToString(unlocking) + " (no secret, no signature)"
}

func TestF004_IRPathRefusesWhatTheValidatorRefuses(t *testing.T) {
	cases := []struct {
		name      string
		ir        string
		source    string // equivalent source the source path refuses ("" = none)
		srcErr    string
		irErr     string
		unlocking []byte // push-only witness an attacker would use
	}{
		{
			name:      "public method with no assert (CL-BUG-216)",
			ir:        noAssertIR,
			source:    noAssertSource,
			srcErr:    "must end with an assert() call",
			irErr:     "must end with an assert",
			unlocking: []byte{0x51}, // OP_1
		},
		{
			name:      "assert not in terminal position",
			ir:        assertThenComputeIR,
			irErr:     "must end with an assert",
			unlocking: []byte{0x51}, // x = 1, secret is 42
		},
		{
			name:      "update_prop on a readonly property",
			ir:        readonlyWriteIR,
			source:    readonlyWriteSource,
			srcErr:    "cannot assign to readonly property 'secret'",
			irErr:     "readonly property 'secret'",
			unlocking: []byte{0x57}, // x = 7, secret is 42
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.source != "" {
				res := CompileFromSourceStrWithResult(tc.source, "Attack.runar.ts")
				var msgs []string
				for _, d := range res.Diagnostics {
					msgs = append(msgs, d.Message)
				}
				if !strings.Contains(strings.Join(msgs, "\n"), tc.srcErr) {
					t.Fatalf("precondition: source path should refuse with %q, got %v", tc.srcErr, msgs)
				}
			}

			artifact, err := CompileFromIRBytes([]byte(tc.ir))
			if err == nil {
				t.Fatalf("--ir path compiled a contract the source validator refuses: script=%s; %s",
					artifact.Script, showSpendableWith(t, artifact.Script, tc.unlocking))
			}
			if !strings.Contains(err.Error(), tc.irErr) {
				t.Fatalf("--ir refused, but not for the stated reason: want %q in %q", tc.irErr, err.Error())
			}
		})
	}
}

// Controls: shapes the source pipeline legitimately produces must still
// compile — both through CompileFromSource (which feeds CompileFromProgram)
// and, after an --emit-ir style JSON round trip, through CompileFromIRBytes:
// a terminal if/else with an assert in each arm, readonly writes in the
// constructor, and update_prop on a mutable property of a stateful contract.
func TestF004_LegitimateShapesStillCompile(t *testing.T) {
	sources := map[string]string{
		"TerminalIfElse.runar.ts": `import { SmartContract, assert } from 'runar-lang';

class TerminalIfElse extends SmartContract {
  readonly limit: bigint;
  constructor(limit: bigint) { super(limit); this.limit = limit; }
  public check(x: bigint, mode: boolean) {
    if (mode) {
      assert(x + 1n > this.limit);
    } else {
      assert(x - 1n < this.limit);
    }
  }
}
`,
		"Counter.runar.ts": `import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;
  readonly step: bigint;
  constructor(count: bigint, step: bigint) { super(count, step); this.count = count; this.step = step; }
  public increment() {
    this.count = this.count + this.step;
  }
}
`,
	}
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := CompileFromSource(path); err != nil {
				t.Fatalf("source path refused a legitimate contract: %v", err)
			}
			program, err := CompileSourceToIR(path, CompileOptions{DisableConstantFolding: true})
			if err != nil {
				t.Fatalf("CompileSourceToIR: %v", err)
			}
			irJSON, err := json.Marshal(program)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CompileFromIRBytes(irJSON); err != nil {
				t.Fatalf("--ir path refused the IR the source path emitted: %v", err)
			}
		})
	}
}
