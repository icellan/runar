package compiler

import (
	"strings"
	"testing"
)

// N-055 — `buildChangeOutput` was callable by name in five tiers and rejected
// by two.
//
// The primitive is the P2PKH change-output serializer the stateful
// continuation epilogue emits (`frontend/anf_lower.go` emits a
// `call buildChangeOutput` into the change gate of every stateful method), and
// `codegen/stack.go#lowerBuildChangeOutput` has always lowered it. What was
// missing in Go — and in Rust — is the row in the typecheck builtin table, so
// the codegen was reachable only through the implicit continuation path and a
// contract that named the function got:
//
//	unknown function 'buildChangeOutput' — only Rúnar built-in functions and
//	contract methods are allowed
//
// while ts / python / zig / ruby / java compiled the same source to
// FIVE_TIER_SCRIPT below. Frontend parity is the invariant with no exceptions,
// and no policy document scopes this primitive to a subset of tiers, so the
// gap was in the SURFACE only: one table row, no codegen change.
//
// The pinned hex decodes to the P2PKH output serialization, which is what
// makes exact equality (rather than "it compiles") the bar here:
//
//	00                  constructor slot — the pubkey hash
//	7b                  OP_ROT
//	04 1976a914         push <varint 25> OP_DUP OP_HASH160 OP_PUSH20
//	7b 7e               OP_ROT OP_CAT       → 1976a914<pkh>
//	02 88ac 7e          push OP_EQUALVERIFY OP_CHECKSIG, OP_CAT
//	7c 58 80            OP_SWAP OP_8 OP_NUM2BIN  → amount as 8-byte LE
//	7c 7e               OP_SWAP OP_CAT      → <amount8><script>
//	7c 87               OP_SWAP OP_EQUAL    → compare against `expected`
const buildChangeOutputProbe = `import { SmartContract, assert, buildChangeOutput } from 'runar-lang';

class ChangeProbe extends SmartContract {
  readonly pkh: ByteString;

  constructor(pkh: ByteString) {
    super(pkh);
    this.pkh = pkh;
  }

  public check(amount: bigint, expected: ByteString): void {
    assert(buildChangeOutput(this.pkh, amount) == expected);
  }
}
`

// The script hex emitted by ts / python / zig / ruby / java for the probe, in
// BOTH fold modes (constant folding cannot reach a runtime `amount`).
const buildChangeOutputFiveTierScript = "007b041976a9147b7e0288ac7e7c58807c7e7c87"

func TestN055_BuildChangeOutput_IsCallableByName(t *testing.T) {
	for _, disableFold := range []bool{true, false} {
		result := CompileFromSourceStrWithResult(
			buildChangeOutputProbe,
			"ChangeProbe.runar.ts",
			CompileOptions{DisableConstantFolding: disableFold},
		)
		if !result.Success {
			var msgs []string
			for _, d := range result.Diagnostics {
				msgs = append(msgs, d.FormatMessage())
			}
			t.Fatalf("disableConstantFolding=%v: buildChangeOutput was rejected: %s",
				disableFold, strings.Join(msgs, "; "))
		}
		if result.Artifact == nil {
			t.Fatalf("disableConstantFolding=%v: expected a non-nil artifact", disableFold)
		}
		if got := result.Artifact.Script; got != buildChangeOutputFiveTierScript {
			t.Errorf("disableConstantFolding=%v: script hex diverged from the peer tiers\n got: %s\nwant: %s",
				disableFold, got, buildChangeOutputFiveTierScript)
		}
	}
}

// The primitive must keep serializing a real P2PKH output, not merely compile.
// A lowering that dropped the amount, the script prefix or the 8-byte LE
// conversion would still satisfy "no diagnostics".
func TestN055_BuildChangeOutput_SerializesAP2PKHOutput(t *testing.T) {
	result := CompileFromSourceStrWithResult(
		buildChangeOutputProbe,
		"ChangeProbe.runar.ts",
		CompileOptions{DisableConstantFolding: true},
	)
	if !result.Success || result.Artifact == nil {
		t.Fatal("probe did not compile; see TestN055_BuildChangeOutput_IsCallableByName")
	}
	script := result.Artifact.Script
	for _, want := range []struct {
		hex, why string
	}{
		{"041976a914", "the <varint 25> OP_DUP OP_HASH160 OP_PUSH20 script prefix"},
		{"0288ac", "the OP_EQUALVERIFY OP_CHECKSIG script suffix"},
		{"5880", "OP_8 OP_NUM2BIN — the amount as an 8-byte little-endian value"},
	} {
		if !strings.Contains(script, want.hex) {
			t.Errorf("script is missing %s (%s): %s", want.hex, want.why, script)
		}
	}
}
