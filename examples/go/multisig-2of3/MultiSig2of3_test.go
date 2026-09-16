package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// R-107 — `multisig-2of3` is the canonical checkMultiSig + array-literal
// example. The two array arguments are the canonical site where the
// `array_literal` ANF node is emitted, and `array_literal` is one of the four
// node kinds `spec/ir-format.md` did not document until R-098.
//
// The port used to carry `//go:build ignore` and a compile-only suite. The tag
// was there because the composite literals were spelled `[N]T{...}`, which does
// not convert to the `[]Sig` / `[]PubKey` the mock CheckMultiSig takes; both
// parsers accept the slice spelling and emit identical ANF, so the port now
// builds and its logic runs here.

const (
	key1 = "0000000000000000000000000000000000000000000000000000000000000001"
	key2 = "0000000000000000000000000000000000000000000000000000000000000002"
	key3 = "0000000000000000000000000000000000000000000000000000000000000003"
	key4 = "0000000000000000000000000000000000000000000000000000000000000004"
)

func newMultiSig() *MultiSig2of3 {
	return &MultiSig2of3{
		Pk1: runar.PubKeyFromPrivKey(key1),
		Pk2: runar.PubKeyFromPrivKey(key2),
		Pk3: runar.PubKeyFromPrivKey(key3),
	}
}

func TestMultiSig2of3_Compile(t *testing.T) {
	if err := runar.CompileCheck("MultiSig2of3.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// OP_CHECKMULTISIG is ORDERED: the supplied signatures must appear in the same
// relative order as their pubkeys in the committed array. Every accepting
// combination is enumerated, and so is the out-of-order form of each -- which
// is the row that separates real ordered verification from a set-membership
// check.
func TestMultiSig2of3_AcceptsAnyOrderedPair(t *testing.T) {
	c := newMultiSig()
	s1, s2, s3 := runar.SignTestMessage(key1), runar.SignTestMessage(key2), runar.SignTestMessage(key3)

	for _, p := range []struct {
		name   string
		a, b   runar.Sig
	}{
		{"pk1+pk2", s1, s2},
		{"pk1+pk3", s1, s3},
		{"pk2+pk3", s2, s3},
	} {
		a, b, name := p.a, p.b, p.name
		mustAccept(t, name+" in committed order", func() { c.Unlock(a, b) })
		mustRefuse(t, name+" reversed", func() { c.Unlock(b, a) })
	}
}

func TestMultiSig2of3_RefusesUncommittedAndDuplicateKeys(t *testing.T) {
	c := newMultiSig()
	s1 := runar.SignTestMessage(key1)
	s4 := runar.SignTestMessage(key4)

	mustRefuse(t, "a signature from a key that is not committed", func() { c.Unlock(s1, s4) })
	mustRefuse(t, "two signatures from an uncommitted key", func() { c.Unlock(s4, s4) })
	// One key cannot satisfy both slots: OP_CHECKMULTISIG consumes a distinct
	// pubkey per signature.
	mustRefuse(t, "the same signature twice", func() { c.Unlock(s1, s1) })
	mustRefuse(t, "garbage signatures", func() {
		c.Unlock(runar.Sig("not-a-signature"), runar.Sig("nor-this"))
	})
}

func mustAccept(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: the contract REFUSED (%v)", what, r)
		}
	}()
	fn()
}

func mustRefuse(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: the contract ACCEPTED where it must refuse", what)
		}
	}()
	fn()
}
