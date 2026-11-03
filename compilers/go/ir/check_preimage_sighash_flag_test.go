package ir

import (
	"fmt"
	"strings"
	"testing"
)

// F-068 / CL-BUG-218: `check_preimage.sighashFlag` arrived from --ir JSON as a
// plain int with no validity check. codegen.checkPreimageBindingBytesWithFlag
// appends `sighashFlag & 0xff` to the on-chain OP_PUSH_TX binding, so an
// out-of-range value was silently truncated to its low byte and emitted at
// exit 0:
//
//	999999 (0xF423F) -> 01 3f   FORKID bit absent
//	-5               -> 01 fb   two's-complement low byte
//	511    (0x1FF)   -> 01 ff
//
// A covenant whose binding demands a FORKID-clear sighash can never be
// satisfied on BSV (the node rejects non-FORKID signatures), so the UTXO is
// permanently unspendable.
//
// The accepted set is the one the TS reference's `@sighash` grammar can
// produce (packages/runar-compiler/src/passes/sighash-directive.ts: exactly one
// base type ALL/NONE/SINGLE, FORKID mandatory, ANYONECANPAY optional):
// {0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3}. An absent field means the default
// ALL|FORKID (0x41).
//
// What this proves: LoadIRFromBytes — the --ir entry point — refuses every
// sighashFlag outside that set (out-of-range, negative, and in-range-but-
// malformed bytes such as 0x3F / 0x01 / 0x40), including inside nested if/loop
// bodies, and still accepts the six valid flags and the absent field unchanged.
// What it does not prove: that the emitted binding for a valid flag verifies on
// chain (covered by the #123 sighash execution tests), nor anything about the
// other six tiers' --ir loaders.

func checkPreimageIR(flagField string, wrap string) string {
	cp := fmt.Sprintf(`{"name": "t1", "value": {"kind": "check_preimage", "preimage": "t0"%s}}`, flagField)
	switch wrap {
	case "if":
		cp = fmt.Sprintf(`{"name": "tc", "value": {"kind": "load_const", "value": true}},
			{"name": "ti", "value": {"kind": "if", "cond": "tc", "then": [%s], "else": []}}`,
			cp)
	case "loop":
		cp = fmt.Sprintf(`{"name": "tl", "value": {"kind": "loop", "count": 1, "iterVar": "i", "body": [%s]}}`, cp)
	}
	return fmt.Sprintf(`{
		"contractName": "SighashFlag",
		"properties": [],
		"methods": [
			{
				"name": "unlock",
				"isPublic": true,
				"params": [{"name": "txPreimage", "type": "SigHashPreimage"}],
				"body": [
					{"name": "t0", "value": {"kind": "load_param", "name": "txPreimage"}},
					%s
				]
			}
		]
	}`, cp)
}

func TestLoadIRFromBytes_RejectsInvalidCheckPreimageSighashFlag(t *testing.T) {
	bad := []int{
		999999, // 0xF423F -> low byte 0x3F, FORKID absent
		-5,     // low byte 0xFB
		511,    // 0x1FF -> low byte 0xFF
		256,    // low byte 0x00
		0x3F,   // in range, FORKID absent
		0x01,   // ALL without FORKID
		0x40,   // FORKID with no base type
		0x44,   // base type 4 does not exist
		0x81,   // ALL|ANYONECANPAY without FORKID
		0xFF,
	}
	for _, wrap := range []string{"top", "if", "loop"} {
		for _, flag := range bad {
			t.Run(fmt.Sprintf("%s/%d", wrap, flag), func(t *testing.T) {
				irJSON := checkPreimageIR(fmt.Sprintf(`, "sighashFlag": %d`, flag), wrap)
				_, err := LoadIRFromBytes([]byte(irJSON))
				if err == nil {
					t.Fatalf("expected LoadIRFromBytes to reject check_preimage sighashFlag=%d, got nil", flag)
				}
				if !strings.Contains(err.Error(), "sighashFlag") {
					t.Errorf("error should name sighashFlag, got: %v", err)
				}
			})
		}
	}
}

func TestLoadIRFromBytes_AcceptsValidCheckPreimageSighashFlag(t *testing.T) {
	for _, flag := range []int{0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3} {
		t.Run(fmt.Sprintf("0x%02x", flag), func(t *testing.T) {
			// N-059: a public method's flag must equal its declared sigHashType.
			prog, err := LoadIRFromBytes([]byte(withSigHashType(checkPreimageIR(fmt.Sprintf(`, "sighashFlag": %d`, flag), "top"), flag)))
			if err != nil {
				t.Fatalf("expected sighashFlag=0x%02x to be accepted, got: %v", flag, err)
			}
			if got := prog.Methods[0].Body[1].Value.SighashFlag; got != flag {
				t.Errorf("sighashFlag changed on load: want 0x%02x, got 0x%02x", flag, got)
			}
		})
	}
	t.Run("absent", func(t *testing.T) {
		if _, err := LoadIRFromBytes([]byte(checkPreimageIR("", "top"))); err != nil {
			t.Fatalf("expected an absent sighashFlag (default ALL|FORKID) to be accepted, got: %v", err)
		}
	})
}

func withSigHashType(irJSON string, sigHashType int) string {
	return strings.Replace(irJSON, `"isPublic": true,`, fmt.Sprintf(`"isPublic": true, "sigHashType": %d,`, sigHashType), 1)
}

// N-059 / F-102: what the typed validateBindings above cannot see. An explicit
// `"sighashFlag": 0` decodes to the same 0 as an absent field, so F-068 let it
// through as "default"; Rust, Python, Ruby, Java and TS emitted it as a 0x00
// byte. And a public method's flag could diverge from the sigHashType its ABI
// declares, so the SDK signed a preimage the script then rejected. Both are now
// refused on the raw document (required_fields.go) with the shared diagnostics.
// Proves: LoadIRFromBytes refuses both shapes at the top level and in if/loop
// bodies, and still accepts a matching pair. Does not prove: the other tiers
// (conformance/negatives/ir-sighash-flag.test.ts drives all seven).
func TestLoadIRFromBytes_RejectsExplicitZeroSighashFlag(t *testing.T) {
	for _, wrap := range []string{"top", "if", "loop"} {
		_, err := LoadIRFromBytes([]byte(checkPreimageIR(`, "sighashFlag": 0`, wrap)))
		if err == nil || !strings.Contains(err.Error(), "check_preimage has sighashFlag 0; sighashFlag must be one of") {
			t.Errorf("%s: expected explicit sighashFlag 0 to be refused, got: %v", wrap, err)
		}
	}
}

func TestLoadIRFromBytes_RejectsSighashFlagSigHashTypeMismatch(t *testing.T) {
	cases := []struct {
		name string
		ir   string
		want string
	}{
		{"flag 0xc3, sigHashType absent", checkPreimageIR(`, "sighashFlag": 195`, "top"), "has sighashFlag 195 but the method declares sigHashType 65"},
		{"flag absent, sigHashType 0xc3", withSigHashType(checkPreimageIR("", "top"), 0xc3), "has sighashFlag 65 but the method declares sigHashType 195"},
		{"flag 0x43, sigHashType 0x42", withSigHashType(checkPreimageIR(`, "sighashFlag": 67`, "top"), 0x42), "has sighashFlag 67 but the method declares sigHashType 66"},
		{"if arm", checkPreimageIR(`, "sighashFlag": 193`, "if"), "has sighashFlag 193 but the method declares sigHashType 65"},
		{"loop body", checkPreimageIR(`, "sighashFlag": 193`, "loop"), "has sighashFlag 193 but the method declares sigHashType 65"},
	}
	for _, c := range cases {
		_, err := LoadIRFromBytes([]byte(c.ir))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: expected refusal containing %q, got: %v", c.name, c.want, err)
		}
	}
}
