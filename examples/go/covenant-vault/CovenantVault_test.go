package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

const minAmount = int64(5000)

func newVault() *CovenantVault {
	return &CovenantVault{
		Owner:     runar.Alice.PubKey,
		Recipient: runar.Bob.PubKeyHash,
		MinAmount: runar.Bigint(minAmount),
	}
}

// p2pkhOutput returns the same byte string the contract builds at runtime.
// In Go-DSL ByteString is a string alias and the ASCII literals "1976a914" /
// "88ac" are NOT hex-decoded — they're concatenated as their raw ASCII bytes.
// We reproduce that exact byte layout so the happy-path hashOutputs check
// round-trips; adversarial cases just need to produce different bytes.
func p2pkhOutput(amount int64, pkh runar.Addr) runar.ByteString {
	amt := runar.Num2Bin(amount, 8)
	return amt + runar.ByteString("1976a914") + runar.ByteString(pkh) + runar.ByteString("88ac")
}

// preimageFromOutputs builds a fake SigHashPreimage whose first 32 bytes are
// hash256(outputsBytes). The Go mock ExtractOutputHash returns exactly those
// 32 bytes, so the contract's hash256(expectedOutput) == ExtractOutputHash
// covenant check sees `outputsBytes` as the committed hashOutputs preimage.
func preimageFromOutputs(outputs runar.ByteString) runar.SigHashPreimage {
	h := runar.Hash256(outputs)
	return runar.SigHashPreimage(string(h))
}

// expectPanic invokes fn and reports a failure if it does NOT panic. Adversarial
// covenant cases must trip a Rúnar Assert and crash with "runar: assertion failed".
func expectPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s: expected panic, got none", name)
		}
	}()
	fn()
}

func TestCovenantVault_Compile(t *testing.T) {
	if err := runar.CompileCheck("CovenantVault.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestCovenantVault_HappyPath(t *testing.T) {
	v := newVault()
	expected := p2pkhOutput(minAmount, v.Recipient)
	preimage := preimageFromOutputs(expected)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	v.Spend(sig, preimage)
}

// -- Adversarial: wrong output count -----------------------------------------

func TestCovenantVault_RejectsZeroOutputs(t *testing.T) {
	v := newVault()
	// hashOutputs commits to no outputs at all (n-1).
	preimage := preimageFromOutputs(runar.ByteString(""))
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	expectPanic(t, "zero-output", func() { v.Spend(sig, preimage) })
}

func TestCovenantVault_RejectsExtraOutput(t *testing.T) {
	v := newVault()
	required := p2pkhOutput(minAmount, v.Recipient)
	extraPkh := runar.Addr(string([]byte{
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	}))
	extra := p2pkhOutput(1000, extraPkh)
	preimage := preimageFromOutputs(required + extra)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	expectPanic(t, "extra-output", func() { v.Spend(sig, preimage) })
}

// -- Adversarial: swapped output order ---------------------------------------

func TestCovenantVault_RejectsReorderedOutputs(t *testing.T) {
	v := newVault()
	required := p2pkhOutput(minAmount, v.Recipient)
	otherPkh := runar.Addr(string([]byte{
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	}))
	other := p2pkhOutput(minAmount, otherPkh)
	// Place the unauthorised output before the required one.
	preimage := preimageFromOutputs(other + required)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	expectPanic(t, "reordered", func() { v.Spend(sig, preimage) })
}

// -- Adversarial: value at boundary ------------------------------------------

func TestCovenantVault_RejectsAmountMinusOne(t *testing.T) {
	v := newVault()
	candidate := p2pkhOutput(minAmount-1, v.Recipient)
	preimage := preimageFromOutputs(candidate)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	expectPanic(t, "amount-1", func() { v.Spend(sig, preimage) })
}

func TestCovenantVault_RejectsAmountPlusOne(t *testing.T) {
	v := newVault()
	candidate := p2pkhOutput(minAmount+1, v.Recipient)
	preimage := preimageFromOutputs(candidate)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	expectPanic(t, "amount+1", func() { v.Spend(sig, preimage) })
}
