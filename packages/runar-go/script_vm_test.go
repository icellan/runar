package runar

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// ---------------------------------------------------------------------------
// One-shot execution
// ---------------------------------------------------------------------------

// TestScriptVM_ExecuteHex_Arithmetic runs "OP_2 OP_3 OP_ADD OP_5 OP_EQUAL"
// (hex 5253935587) — 2 + 3 == 5 — and expects a truthy result.
func TestScriptVM_ExecuteHex_Arithmetic(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	res, err := vm.ExecuteHex("5253935587")
	if err != nil {
		t.Fatalf("ExecuteHex returned wrapper error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %q", res.Error)
	}
	if len(res.Stack) != 1 {
		t.Fatalf("expected 1 stack item, got %d: %x", len(res.Stack), res.Stack)
	}
	if len(res.Stack[0]) != 1 || res.Stack[0][0] != 0x01 {
		t.Errorf("expected truthy [01] on top, got %x", res.Stack[0])
	}
	if res.OpsExecuted != 5 {
		t.Errorf("expected 5 ops executed, got %d", res.OpsExecuted)
	}
}

// TestScriptVM_ExecuteHex_Failure runs "OP_2 OP_3 OP_EQUAL" (5253 87) —
// 2 == 3 is false — and expects a non-successful result with a clean-stack
// failure (top of stack is false / empty).
func TestScriptVM_ExecuteHex_Failure(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	res, err := vm.ExecuteHex("525387")
	if err != nil {
		t.Fatalf("ExecuteHex returned wrapper error: %v", err)
	}
	if res.Success {
		t.Fatalf("expected failure for 2 == 3, got success with stack %x", res.Stack)
	}
}

// TestScriptVM_Execute_UnlockingAndLocking executes a split unlocking +
// locking pair: unlocking pushes OP_5, locking checks "dup, 5, equal".
func TestScriptVM_Execute_UnlockingAndLocking(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	// unlocking: OP_5            -> 55
	// locking:   OP_5 OP_EQUAL   -> 5587
	res, err := vm.Execute([]byte{0x55}, []byte{0x55, 0x87})
	if err != nil {
		t.Fatalf("Execute returned wrapper error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %q", res.Error)
	}
}

// TestScriptVM_ExecuteHex_InvalidHex rejects malformed hex with a wrapper
// error (not a VMResult).
func TestScriptVM_ExecuteHex_InvalidHex(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	if _, err := vm.ExecuteHex("xyz"); err == nil {
		t.Fatal("expected an error for invalid hex input")
	}
}

// ---------------------------------------------------------------------------
// Step mode (debugger API)
// ---------------------------------------------------------------------------

// TestScriptVM_StepMode walks "OP_2 OP_3 OP_ADD OP_5 OP_EQUAL" one opcode at
// a time and asserts the opcode names and intermediate stack depths.
func TestScriptVM_StepMode(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	if err := vm.LoadHex("", "5253935587"); err != nil {
		t.Fatalf("LoadHex failed: %v", err)
	}

	wantOpcodes := []string{"OP_2", "OP_3", "OP_ADD", "OP_5", "OP_EQUAL"}
	wantDepth := []int{1, 2, 1, 2, 1} // main-stack depth after each opcode

	var seen []string
	for i := 0; ; i++ {
		step := vm.Step()
		if step == nil {
			break
		}
		if i >= len(wantOpcodes) {
			t.Fatalf("more steps than expected; extra opcode %q", step.Opcode)
		}
		if step.Opcode != wantOpcodes[i] {
			t.Errorf("step %d: expected opcode %q, got %q", i, wantOpcodes[i], step.Opcode)
		}
		if len(step.MainStack) != wantDepth[i] {
			t.Errorf("step %d (%s): expected main-stack depth %d, got %d",
				i, step.Opcode, wantDepth[i], len(step.MainStack))
		}
		if step.Context != "locking" {
			t.Errorf("step %d: expected context 'locking', got %q", i, step.Context)
		}
		seen = append(seen, step.Opcode)
	}

	if len(seen) != len(wantOpcodes) {
		t.Fatalf("expected %d steps, got %d: %v", len(wantOpcodes), len(seen), seen)
	}
	if !vm.IsComplete() {
		t.Error("expected IsComplete() == true after walking the whole trace")
	}
	if !vm.IsSuccess() {
		t.Error("expected IsSuccess() == true for 2 + 3 == 5")
	}
	if vm.PC() != 5 {
		t.Errorf("expected PC() == 5 after stepping, got %d", vm.PC())
	}
}

// TestScriptVM_StepMode_ContextTransition confirms the cursor reports the
// "unlocking" context for opcodes from the unlocking script and "locking"
// for the locking script.
func TestScriptVM_StepMode_ContextTransition(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	// unlocking: OP_5 (55), locking: OP_5 OP_EQUAL (5587)
	if err := vm.LoadHex("55", "5587"); err != nil {
		t.Fatalf("LoadHex failed: %v", err)
	}

	step1 := vm.Step()
	if step1 == nil || step1.Context != "unlocking" {
		t.Fatalf("step 1: expected unlocking context, got %+v", step1)
	}
	step2 := vm.Step()
	if step2 == nil || step2.Context != "locking" {
		t.Fatalf("step 2: expected locking context, got %+v", step2)
	}
	step3 := vm.Step()
	if step3 == nil || step3.Context != "locking" {
		t.Fatalf("step 3: expected locking context, got %+v", step3)
	}
	if vm.Step() != nil {
		t.Error("expected nil after the final opcode")
	}
}

// TestScriptVM_Step_NothingLoaded returns nil when Step is called before any
// Load/Execute.
func TestScriptVM_Step_NothingLoaded(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	if vm.Step() != nil {
		t.Error("expected Step() == nil when nothing is loaded")
	}
	if vm.IsComplete() {
		t.Error("expected IsComplete() == false when nothing is loaded")
	}
}

// ---------------------------------------------------------------------------
// Signature-checking scripts (F-124)
// ---------------------------------------------------------------------------

// tsP2PKHLockingHex / tsP2PKHUnlockingHex are a real P2PKH spend produced by
// the TypeScript ScriptVM's own synthetic spend context
// (packages/runar-testing/src/vm/script-vm.ts SYNTHETIC_SPEND_CONTEXT):
// private key 1, SIGHASH_ALL|FORKID, BIP-143 preimage over the single-input,
// zero-output spend of the null outpoint (version 1, 100000 sats, sequence
// 0xffffffff, locktime 0). The TS ScriptVM reports success for this pair. The
// signature only verifies if the Go VM's synthetic transaction is the same.
const (
	tsP2PKHLockingHex   = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
	tsP2PKHUnlockingHex = "4730440220459bb2da0b81e7a5b8aba3116a4ef6e2df9695b3d795af3ae30b5a928c1443ca022044a077326ac6221fb76ee4629bd014d65357786e3577601846db5188721bf3db41210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

// syntheticSpendSighash computes, independently of script_vm.go, the BIP-143
// sighash of the TS ScriptVM's synthetic spend context for the given locking
// script, under the given transaction version.
func syntheticSpendSighash(t *testing.T, locking []byte, version uint32) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.Version = version
	tx.LockTime = 0
	in := &transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	}
	in.SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      100_000,
		LockingScript: bsvscript.NewFromBytes(locking),
	})
	tx.Inputs = append(tx.Inputs, in)
	h, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		t.Fatalf("CalcInputSignatureHash: %v", err)
	}
	return h
}

// p2pkhSpend builds a P2PKH locking script for lockKey and an unlocking script
// carrying lockKey's pubkey plus a signature by sigKey over the synthetic
// spend context at the given tx version.
func p2pkhSpend(t *testing.T, lockKey, sigKey *ec.PrivateKey, version uint32) (unlocking, locking []byte) {
	t.Helper()
	pub := lockKey.PubKey().Compressed()
	locking = append([]byte{0x76, 0xa9, 0x14}, []byte(Hash160(PubKey(pub)))...)
	locking = append(locking, 0x88, 0xac)
	sig, err := sigKey.Sign(syntheticSpendSighash(t, locking, version))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigBytes := append(sig.Serialize(), byte(sighash.AllForkID))
	unlocking = append([]byte{byte(len(sigBytes))}, sigBytes...)
	unlocking = append(unlocking, byte(len(pub)))
	unlocking = append(unlocking, pub...)
	return unlocking, locking
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestScriptVM_P2PKH_TSVector_Succeeds proves the Go ScriptVM evaluates
// OP_CHECKSIG against the same synthetic spend context as the TS ScriptVM: a
// signature the TS VM accepts is accepted here.
//
// Proves: signature-check opcodes run (no parse-time rejection) and the
// synthetic tx (version, outpoint, amount, sequence, locktime, no outputs)
// is byte-identical to TS's for SIGHASH_ALL|FORKID.
// Does not prove: other sighash scopes, multi-input/output contexts, or any
// contract-level property — this is a single P2PKH spend.
func TestScriptVM_P2PKH_TSVector_Succeeds(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	res, err := vm.Execute(mustHex(t, tsP2PKHUnlockingHex), mustHex(t, tsP2PKHLockingHex))
	if err != nil {
		t.Fatalf("Execute returned wrapper error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected the TS-signed P2PKH spend to succeed, got error %q (ops executed %d)", res.Error, res.OpsExecuted)
	}
	// 2 unlocking pushes + DUP HASH160 PUSH EQUALVERIFY CHECKSIG.
	if res.OpsExecuted != 7 {
		t.Errorf("expected 7 ops executed, got %d", res.OpsExecuted)
	}
}

// TestScriptVM_P2PKH_SignatureIsActuallyChecked shows Success reflects the
// signature: a correct Go-signed spend succeeds; a spend whose pubkey matches
// the hash but whose signature is by a different key fails AT OP_CHECKSIG
// (which pushes false), not at parse time or at OP_EQUALVERIFY; and a
// signature over a different transaction version (a drifted context) fails
// the same way.
//
// Proves: OP_CHECKSIG verifies real secp256k1 signatures over the synthetic
// BIP-143 preimage, so a wrong key or wrong context is rejected for the
// signature reason.
// Does not prove: behaviour under VMOptions{ForkID: true} (strict encoding)
// or of OP_CHECKMULTISIG.
func TestScriptVM_P2PKH_SignatureIsActuallyChecked(t *testing.T) {
	keyA, _ := ec.PrivateKeyFromBytes([]byte{0x11})
	keyB, _ := ec.PrivateKeyFromBytes([]byte{0x22})

	unlock, lock := p2pkhSpend(t, keyA, keyA, 1)
	res, _ := NewScriptVM(VMOptions{}).Execute(unlock, lock)
	if !res.Success {
		t.Fatalf("correct-key spend: expected success, got error %q (ops %d)", res.Error, res.OpsExecuted)
	}

	cases := []struct {
		name    string
		sigKey  *ec.PrivateKey
		version uint32
	}{
		{"wrong key", keyB, 1},
		{"wrong tx version", keyA, 2},
	}
	for _, c := range cases {
		unlock, lock := p2pkhSpend(t, keyA, c.sigKey, c.version)
		vm := NewScriptVM(VMOptions{})
		if err := vm.Load(unlock, lock); err != nil {
			t.Fatalf("%s: Load: %v", c.name, err)
		}
		var last *StepResult
		for s := vm.Step(); s != nil; s = vm.Step() {
			last = s
		}
		if vm.IsSuccess() {
			t.Fatalf("%s: expected failure, got success", c.name)
		}
		if last == nil || last.Opcode != "OP_CHECKSIG" {
			t.Fatalf("%s: expected execution to reach OP_CHECKSIG, last step %+v", c.name, last)
		}
		top := last.MainStack[len(last.MainStack)-1]
		if len(top) != 0 {
			t.Errorf("%s: expected OP_CHECKSIG to push false, got %x", c.name, top)
		}
	}
}

// TestScriptVM_StepMode_P2PKH walks the TS-signed P2PKH spend in step mode:
// the step API keeps working with the transaction context attached.
func TestScriptVM_StepMode_P2PKH(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	if err := vm.LoadHex(tsP2PKHUnlockingHex, tsP2PKHLockingHex); err != nil {
		t.Fatalf("LoadHex failed: %v", err)
	}
	want := []string{"OP_DATA_71", "OP_DATA_33", "OP_DUP", "OP_HASH160", "OP_DATA_20", "OP_EQUALVERIFY", "OP_CHECKSIG"}
	var got []string
	var last *StepResult
	for s := vm.Step(); s != nil; s = vm.Step() {
		got = append(got, s.Opcode)
		last = s
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d steps %v, got %d: %v", len(want), want, len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step %d: expected %q, got %q", i, want[i], got[i])
		}
	}
	if last.Context != "locking" {
		t.Errorf("expected final step in locking context, got %q", last.Context)
	}
	if !vm.IsComplete() || !vm.IsSuccess() {
		t.Errorf("expected complete+success, got complete=%v success=%v", vm.IsComplete(), vm.IsSuccess())
	}
}

// TestScriptVM_Result_ExposesLoadError shows a step-mode caller can read why
// a loaded script produced no steps (previously the interpreter error was
// stored in an unexported field with no accessor).
func TestScriptVM_Result_ExposesLoadError(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	// OP_PUSHDATA1 with a missing length byte: a parse-time failure.
	if err := vm.LoadHex("", "4c"); err != nil {
		t.Fatalf("LoadHex failed: %v", err)
	}
	if vm.Step() != nil {
		t.Fatal("expected no steps for an unparseable script")
	}
	res := vm.Result()
	if res == nil || res.Success || res.Error == "" {
		t.Fatalf("expected Result() to carry the interpreter error, got %+v", res)
	}
}
