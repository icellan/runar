package runar

// #213, SDK side — defence in depth only.
//
// A stateful method's unlocking script pushes the compiler-injected
// `_changePKH` (a Ripemd160, exactly 20 bytes). The consensus defence is the
// covenant's entry gate on its width (OP_SIZE 0x14 OP_NUMEQUALVERIFY). The SDK
// derives the change PKH as hash160(pubkey), always 20 bytes; encodeChangePKH
// is the single encoder every change-PKH push site goes through, and refuses
// anything that is not exactly 20 bytes of hex before a transaction is built.
// Proves nothing on chain.

import (
	"strings"
	"testing"
)

func TestPrB_EncodeChangePKH_RefusesWrongWidth(t *testing.T) {
	for _, n := range []int{19, 21, 54} {
		_, err := encodeChangePKH(strings.Repeat("ab", n))
		if err == nil {
			t.Fatalf("%d-byte changePKH: expected refusal, got nil", n)
		}
		if !strings.Contains(err.Error(), "changePKH (Ripemd160) must be exactly 20 bytes") {
			t.Fatalf("%d-byte changePKH: unexpected error %q", n, err)
		}
	}
}

func TestPrB_EncodeChangePKH_RefusesNonHex(t *testing.T) {
	_, err := encodeChangePKH(strings.Repeat("zz", 20))
	if err == nil || !strings.Contains(err.Error(), "changePKH (Ripemd160) must be exactly 20 bytes of hex, got a non-hex string") {
		t.Fatalf("non-hex changePKH: expected refusal, got %v", err)
	}
}

func TestPrB_EncodeChangePKH_Accepts20Bytes(t *testing.T) {
	pkh := strings.Repeat("ab", 20)
	got, err := encodeChangePKH(pkh)
	if err != nil {
		t.Fatalf("20-byte changePKH refused: %v", err)
	}
	if got != "14"+pkh {
		t.Fatalf("20-byte changePKH: got %q, want %q", got, "14"+pkh)
	}
}
