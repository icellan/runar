package runar

// N-073: a fixed-width ByteString-family constructor arg must have its declared
// width (Addr/Ripemd160 20, Sha256 32, PubKey 33, Point/P256Point 64,
// P384Point 96), with N-045's message. FromUtxo's internal restore path is
// unaffected.
//
// PROVES: a 33-byte Sha256 and a 19-byte Addr (scalar, []byte, FixedArray leaf)
// panic with *InvalidConstructorArgError carrying the N-045 wording; correct
// widths are accepted; ByteString takes any length; FromUtxo restores.
// DOES NOT PROVE: method-call or state value widths (N-045), on-chain
// spendability, or that the restore bypass is unreachable by user input.

import (
	"errors"
	"strings"
	"testing"
)

func n073Hex(n int) string { return strings.Repeat("ab", n) }

func TestN073_WrongWidthCtorArgIsRefused(t *testing.T) {
	_, err := n329Construct(n329Artifact("Sha256", nil), n073Hex(33))
	var bad *InvalidConstructorArgError
	if !errors.As(err, &bad) {
		t.Fatalf("want *InvalidConstructorArgError, got %v", err)
	}
	if !strings.Contains(err.Error(), "must be exactly 32 bytes of hex, got 33 bytes") {
		t.Fatalf("message lacks N-045 wording: %v", err)
	}

	for name, arg := range map[string]interface{}{
		"string":  n073Hex(19),
		"[]byte":  make([]byte, 19),
		"ByteStr": ByteString(n073Hex(19)),
	} {
		_, err := n329Construct(n329Artifact("Addr", nil), arg)
		if !errors.As(err, &bad) {
			t.Fatalf("%s: want *InvalidConstructorArgError, got %v", name, err)
		}
	}

	a := n329Artifact("FixedArray<Addr, 2>", &ABIFixedArray{ElementType: "Addr", Length: 2})
	if _, err := n329Construct(a, []interface{}{n073Hex(20), n073Hex(19)}); !errors.As(err, &bad) {
		t.Fatalf("FixedArray leaf: want *InvalidConstructorArgError, got %v", err)
	}
}

func TestN073_CorrectWidthIsAcceptedAndOneLessRefused(t *testing.T) {
	for typ, n := range map[string]int{
		"Addr": 20, "Ripemd160": 20, "Sha256": 32, "PubKey": 33,
		"Point": 64, "P256Point": 64, "P384Point": 96,
	} {
		if _, err := n329Construct(n329Artifact(typ, nil), n073Hex(n)); err != nil {
			t.Fatalf("%s: correct width refused: %v", typ, err)
		}
		if _, err := n329Construct(n329Artifact(typ, nil), n073Hex(n-1)); err == nil {
			t.Fatalf("%s: %d-byte arg accepted", typ, n-1)
		}
	}
	if _, err := n329Construct(n329Artifact("ByteString", nil), n073Hex(3)); err != nil {
		t.Fatalf("ByteString of any length must be accepted: %v", err)
	}
}

func TestN073_FromUtxoStillRestores(t *testing.T) {
	a := n329Artifact("Addr", nil)
	c, err := n329Construct(a, n073Hex(20))
	if err != nil {
		t.Fatal(err)
	}
	script := c.GetLockingScript()
	if _, err := FromUtxo(a, UTXO{Txid: strings.Repeat("00", 32), OutputIndex: 0, Satoshis: 1, Script: script}); err != nil {
		t.Fatalf("FromUtxo: %v", err)
	}
}
