package runar

// GK-BUG-013 (off-chain half, Go tier): Sha256Finalize must refuse a msgBitLen
// outside [0, 2^64), the domain the compiled script enforces with its
// `<00> OP_EQUALVERIFY` sign-byte check. It used to write uint64(msgBitLen),
// so -24 wrapped to 2^64 - 24 and produced a digest no script computes.
// int64 cannot hold 2^64 or more, so the negative half is the whole Go case.
//
// Proves: -24 and math.MinInt64 panic with the shared "msgBitLen must be in
// [0, 2^64)" diagnostic; 24 still yields SHA-256("abc") (crypto/sha256 is the
// oracle); math.MaxInt64 rounded down to a multiple of 8 is accepted.
// Does not prove: the other six tiers (each has its own gk-bug-013 test).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"
)

const gk013IV = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"

func gk013Finalize(t *testing.T, bitLen int64) (out ByteString, panicMsg string) {
	t.Helper()
	iv, _ := hex.DecodeString(gk013IV)
	defer func() {
		if r := recover(); r != nil {
			panicMsg = fmt.Sprint(r)
		}
	}()
	out = Sha256Finalize(ByteString(iv), ByteString("abc"), bitLen)
	return out, ""
}

func TestGkBug013_Sha256Finalize_HonestLengthStillHashes(t *testing.T) {
	want := sha256.Sum256([]byte("abc"))
	got, msg := gk013Finalize(t, 24)
	if msg != "" {
		t.Fatalf("Sha256Finalize(IV, abc, 24) panicked: %s", msg)
	}
	if hex.EncodeToString([]byte(got)) != hex.EncodeToString(want[:]) {
		t.Fatalf("Sha256Finalize(IV, abc, 24) = %x, want %x", []byte(got), want)
	}
}

func TestGkBug013_Sha256Finalize_RefusesNegativeBitLen(t *testing.T) {
	for _, bitLen := range []int64{-24, -1, math.MinInt64} {
		_, msg := gk013Finalize(t, bitLen)
		if msg == "" {
			t.Fatalf("Sha256Finalize(IV, abc, %d) returned a digest; want a refusal", bitLen)
		}
		if !strings.Contains(msg, "msgBitLen must be in [0, 2^64)") {
			t.Fatalf("Sha256Finalize(IV, abc, %d) panicked with %q; want the msgBitLen domain diagnostic", bitLen, msg)
		}
		if !strings.Contains(msg, fmt.Sprintf("got %d", bitLen)) {
			t.Fatalf("diagnostic %q does not name the value %d", msg, bitLen)
		}
	}
}

func TestGkBug013_Sha256Finalize_AcceptsTopOfInt64(t *testing.T) {
	_, msg := gk013Finalize(t, math.MaxInt64&^7)
	if msg != "" {
		t.Fatalf("Sha256Finalize(IV, abc, MaxInt64 &^ 7) panicked: %s", msg)
	}
}
