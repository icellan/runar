package compiler

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// scriptOp is one decoded Script opcode: its byte offset and opcode byte.
// Push payloads are skipped, never reported as opcodes.
type scriptOp struct {
	offset int
	code   byte
}

// decodeScriptOps hex-decodes a script and walks it opcode by opcode,
// skipping direct pushes (0x01-0x4b) and OP_PUSHDATA1/2/4 payloads, so a
// 0xaa that sits inside pushed data is not reported as OP_HASH256 and a
// match can never straddle a nibble boundary of the hex string.
func decodeScriptOps(t *testing.T, scriptHex string) []scriptOp {
	t.Helper()
	b, err := hex.DecodeString(scriptHex)
	if err != nil {
		t.Fatalf("script is not valid hex: %v", err)
	}
	var ops []scriptOp
	for i := 0; i < len(b); {
		c := b[i]
		ops = append(ops, scriptOp{offset: i, code: c})
		n := 1
		switch {
		case c >= 0x01 && c <= 0x4b:
			n += int(c)
		case c == 0x4c && i+1 < len(b):
			n += 1 + int(b[i+1])
		case c == 0x4d && i+2 < len(b):
			n += 2 + int(b[i+1]) + int(b[i+2])<<8
		case c == 0x4e && i+4 < len(b):
			n += 4 + int(b[i+1]) + int(b[i+2])<<8 + int(b[i+3])<<16 + int(b[i+4])<<24
		}
		i += n
	}
	return ops
}

// lastOpIndex returns the index in ops of the last occurrence of code, or -1.
func lastOpIndex(ops []scriptOp, code byte) int {
	for i := len(ops) - 1; i >= 0; i-- {
		if ops[i].code == code {
			return i
		}
	}
	return -1
}

// equalityWithin reports whether OP_EQUAL (0x87) or OP_EQUALVERIFY (0x88)
// is an opcode starting within maxBytes bytes after ops[idx].
func equalityWithin(ops []scriptOp, idx, maxBytes int) bool {
	for _, op := range ops[idx+1:] {
		if op.offset > ops[idx].offset+maxBytes {
			break
		}
		if op.code == 0x87 || op.code == 0x88 {
			return true
		}
	}
	return false
}

// TestDecodeScriptOps_IsByteAndPushAligned proves the opcode-audit helpers
// used below are not the nibble-unaligned hex substring search they replace
// (F-178). "1aa2" contains the substring "aa" but no 0xaa byte; "01aa" is
// a push OF 0xaa, not an OP_HASH256; "aa87" is a real OP_HASH256 followed by
// OP_EQUAL. It does not prove anything about what the compiler emits.
func TestDecodeScriptOps_IsByteAndPushAligned(t *testing.T) {
	cases := []struct {
		name       string
		hex        string
		hasHash    bool
		hashThenEq bool
	}{
		{"nibble-straddling 1aa2", "1aa2", false, false},
		{"0xaa inside direct push 01aa", "01aa", false, false},
		{"0xaa inside PUSHDATA1 4c01aa", "4c01aa", false, false},
		{"real OP_HASH256 aa", "aa", true, false},
		{"real OP_HASH256 then OP_EQUAL", "aa87", true, true},
		{"real OP_HASH256 then OP_EQUALVERIFY", "aa88", true, true},
		{"0x87 inside push after hash aa 0187", "aa0187", true, false},
	}
	for _, c := range cases {
		ops := decodeScriptOps(t, c.hex)
		idx := lastOpIndex(ops, 0xaa)
		if (idx >= 0) != c.hasHash {
			t.Errorf("%s: OP_HASH256 found=%v, want %v", c.name, idx >= 0, c.hasHash)
		}
		if idx >= 0 && equalityWithin(ops, idx, 8) != c.hashThenEq {
			t.Errorf("%s: equality after hash=%v, want %v", c.name, equalityWithin(ops, idx, 8), c.hashThenEq)
		}
	}
	// Documents the vacuous behaviour of the old check on the crafted input.
	if !strings.Contains("1aa2", "aa") {
		t.Fatal("control: the old substring check must match the nibble-straddling input")
	}
}

// TestIntentIntrinsics_EndToEndCompile verifies that a contract exercising
// all three intent-covenant intrinsics (extractPrevOutputScript,
// requireOutputP2PKH, currentBlockHeight) compiles cleanly from Go source
// to Bitcoin Script hex. The compiled artifact must include the
// auto-injected witness parameters in its ABI.
func TestIntentIntrinsics_EndToEndCompile(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentDemo struct {
	runar.StatefulSmartContract
	StateCovScriptHash runar.ByteString ` + "`runar:\"readonly\"`" + `
	BondPKH            runar.ByteString ` + "`runar:\"readonly\"`" + `
	BondAmount         runar.Bigint     ` + "`runar:\"readonly\"`" + `
	Deadline           runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *IntentDemo) CoSpendPrivileged() {
	stateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
	_ = stateCovScript

	h := runar.CurrentBlockHeight()
	runar.Assert(h <= c.Deadline)

	runar.RequireOutputP2PKH(0, c.BondPKH, c.BondAmount)
}
`
	result := CompileFromSourceStrWithResult(source, "IntentDemo.runar.go")
	if !result.Success {
		var msgs []string
		for _, d := range result.Diagnostics {
			msgs = append(msgs, d.FormatMessage())
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "; "))
	}
	if result.Artifact == nil {
		t.Fatal("expected non-nil artifact on success")
	}
	if result.Artifact.Script == "" {
		t.Fatal("expected non-empty Script hex in compiled artifact")
	}

	// Opcode-sequence audit (per BSVM Phase 13 review minor): the emitted
	// Script for the combined intrinsics body MUST contain OP_HASH256
	// (0xaa) — both the extractPrevOutputScript bridge hash AND the
	// requireOutputP2PKH hashOutputs check use OP_HASH256. The stack
	// scaffolding around them may evolve; we only assert the load-bearing
	// primitive shows up.
	if lastOpIndex(decodeScriptOps(t, result.Artifact.Script), 0xaa) < 0 {
		t.Errorf("expected OP_HASH256 (`aa`) opcode in compiled script; bridge hash assertions missing. Hex: %s", result.Artifact.Script)
	}

	// Locate the public method's ABI entry. The auto-injected witness
	// params must appear after the user-facing params.
	var foundMethod bool
	for _, m := range result.Artifact.ABI.Methods {
		if m.Name != "coSpendPrivileged" {
			continue
		}
		foundMethod = true
		paramNames := make(map[string]bool)
		var got []string
		for _, p := range m.Params {
			paramNames[p.Name] = true
			got = append(got, p.Name)
		}
		for _, want := range []string{"_prevOutScript_0", "_serialisedOutputs", "txPreimage"} {
			if !paramNames[want] {
				t.Errorf("expected param %q in coSpendPrivileged ABI; got: %v", want, got)
			}
		}
		break
	}
	if !foundMethod {
		var names []string
		for _, m := range result.Artifact.ABI.Methods {
			names = append(names, m.Name)
		}
		t.Fatalf("method coSpendPrivileged not found in artifact ABI; got: %v", names)
	}
}

// TestIntentIntrinsics_ExtractPrevOutputScriptOnly checks the simplest
// single-intrinsic compile path (just the witness-bridge for input 0).
//
// Performs a deeper opcode-sequence audit than the combined-fixture test —
// asserts (1) OP_HASH256 (0xaa) appears AND (2) is followed within a
// narrow window by OP_EQUAL (0x87) or OP_EQUALVERIFY (0x88), proving the
// hash is being compared against an expected value (not just left on the
// stack). This catches a regression where the lowering passes drop the
// equality assertion after computing hash256.
func TestIntentIntrinsics_ExtractPrevOutputScriptOnly(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type MinIntent struct {
	runar.StatefulSmartContract
	H runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *MinIntent) Bind() {
	s := runar.ExtractPrevOutputScript(0, c.H)
	_ = s
}
`
	result := CompileFromSourceStrWithResult(source, "MinIntent.runar.go")
	if !result.Success {
		var msgs []string
		for _, d := range result.Diagnostics {
			msgs = append(msgs, d.FormatMessage())
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "; "))
	}
	if result.Artifact.Script == "" {
		t.Fatal("expected non-empty hex")
	}

	hex := result.Artifact.Script
	ops := decodeScriptOps(t, hex)
	idx := lastOpIndex(ops, 0xaa)
	if idx < 0 {
		t.Fatalf("expected OP_HASH256 (`aa`) opcode in compiled script; missing the witness-bridge hash assertion. Hex: %s", hex)
	}

	// Find OP_HASH256 and assert OP_EQUAL (0x87) or OP_EQUALVERIFY (0x88)
	// appears as an opcode within the next 8 bytes, proving the hash
	// is being compared. The script is decoded to bytes and walked opcode
	// by opcode (push payloads skipped), so neither a nibble-straddling
	// hex match nor a 0xaa/0x87 inside pushed data counts. Use the LAST
	// OP_HASH256: the auto-injected checkPreimage
	// prologue is an opaque OP_PUSH_TX blob that contains its own earlier
	// OP_HASH256 (hash256(preimage)); the witness-bridge hash256→equality
	// is the LAST OP_HASH256 in the script (BUG-100 fix).
	if !equalityWithin(ops, idx, 8) {
		t.Errorf("expected OP_EQUAL (`87`) or OP_EQUALVERIFY (`88`) opcode within 8 bytes after OP_HASH256 (op #%d, byte offset %d); the bridge equality is not enforced. Full hex: %s", idx, ops[idx].offset, hex)
	}

	// The auto-injected `_prevOutScript_0` MUST be the last ABI param
	// after txPreimage (matching the auto-injection ordering documented
	// in docs/cross-covenant-pattern.md). Verify ordering, not just
	// presence — out-of-order witness params would break SDK consumers
	// that build the unlocking script by ABI position.
	for _, m := range result.Artifact.ABI.Methods {
		if m.Name != "bind" {
			continue
		}
		var names []string
		for _, p := range m.Params {
			names = append(names, p.Name)
		}
		txPreimageIdx, prevOutScriptIdx := -1, -1
		for i, n := range names {
			if n == "txPreimage" {
				txPreimageIdx = i
			}
			if n == "_prevOutScript_0" {
				prevOutScriptIdx = i
			}
		}
		if txPreimageIdx < 0 {
			t.Errorf("expected txPreimage in bind ABI; got %v", names)
		}
		if prevOutScriptIdx < 0 {
			t.Errorf("expected _prevOutScript_0 in bind ABI; got %v", names)
		}
		if prevOutScriptIdx >= 0 && txPreimageIdx >= 0 && prevOutScriptIdx <= txPreimageIdx {
			t.Errorf("_prevOutScript_0 (idx=%d) must come after txPreimage (idx=%d) per auto-injection ordering; got %v", prevOutScriptIdx, txPreimageIdx, names)
		}
		break
	}
}

// TestIntentIntrinsics_RequireOutputP2PKH_OnceOnlyHashCheck verifies that
// when multiple requireOutputP2PKH calls appear in the same method body,
// the hashOutputs check is emitted EXACTLY ONCE (per the idempotency
// contract in the dispatch code). Counts OP_HASH256 occurrences and
// asserts the count matches: 1 (hashOutputs assertion) + N (per-output
// P2PKH hash), where N = number of distinct output indices.
//
// This guards against a regression where the methodScope.didEmitHashOutputsCheck
// flag gets reset between calls, doubling the emitted hashOutputs check
// and bloating the script.
func TestIntentIntrinsics_RequireOutputP2PKH_OnceOnlyHashCheck(t *testing.T) {
	// Two RequireOutputP2PKH calls, same method — should produce exactly
	// ONE hashOutputs check, NOT two.
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Two struct {
	runar.StatefulSmartContract
	PKH1 runar.ByteString ` + "`runar:\"readonly\"`" + `
	PKH2 runar.ByteString ` + "`runar:\"readonly\"`" + `
	A1   runar.Bigint     ` + "`runar:\"readonly\"`" + `
	A2   runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *Two) Bind() {
	// W2: both calls name index 0 -- any literal index above 0 is refused now.
	runar.RequireOutputP2PKH(0, c.PKH1, c.A1)
	runar.RequireOutputP2PKH(0, c.PKH2, c.A2)
}
`
	// Compile via the source-to-IR path so we get the ANF directly,
	// independent of whether Artifact.ANF is populated for this contract
	// shape. Counting hash256 in ANF is authoritative — counting `aa`
	// bytes in compiled hex would over-count any 0xaa in pushdata.
	tmpFile := writeTempGoSource(t, "Two.runar.go", source)
	program, err := CompileSourceToIR(tmpFile)
	if err != nil {
		t.Fatalf("CompileSourceToIR failed: %v", err)
	}
	var foundMethod bool
	for _, m := range program.Methods {
		if m.Name != "bind" {
			continue
		}
		foundMethod = true
		hash256Count := 0
		for _, b := range m.Body {
			if b.Value.Kind == "call" && b.Value.Func == "hash256" {
				hash256Count++
			}
		}
		// Expected hash256 count:
		// - 1 for the once-per-method hashOutputs(serialised) check
		// - 0 for the per-output assertion (uses Substr equality, not hash)
		// = 1 total
		// Anything > 1 means the dispatch lost its idempotency flag.
		if hash256Count != 1 {
			t.Errorf("expected exactly 1 hash256 call (once-per-method hashOutputs check) for two requireOutputP2PKH calls in same body; got %d. Idempotency regression?", hash256Count)
		}
		break
	}
	if !foundMethod {
		t.Fatal("method 'bind' not found in ANF")
	}
}

// writeTempGoSource writes a Go-DSL source string to a temp file with the
// given basename and returns the path. Cleanup is automatic via t.TempDir.
func writeTempGoSource(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/" + name
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeTempGoSource: %v", err)
	}
	return path
}
