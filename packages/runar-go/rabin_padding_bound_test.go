package runar

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

// TestRabinPaddingBound_RejectsForgery verifies the off-chain verifier rejects
// the universal forgery (sig=0, padding=SHA256(msg)) that the on-chain script
// rejects via the RABIN_PADDING_LIMIT OP_WITHIN bound. Without the padding
// bound, (0^2 + SHA256(msg)) mod n == SHA256(msg) mod n verifies for any msg.
func TestRabinPaddingBound_RejectsForgery(t *testing.T) {
	msg := []byte("attack at dawn")

	h := sha256.Sum256(msg)
	// padding = SHA256(msg) as raw bytes (>= 65536, so must be rejected).
	forgedPadding := h[:]
	sigZero := []byte{0}

	if rabinVerifyImpl(msg, sigZero, forgedPadding, []byte(RabinTestKeyN)) {
		t.Fatal("forgery accepted: sig=0, padding=SHA256(msg) must be rejected by the padding bound")
	}
}

// TestRabinPaddingBound_AcceptsHonestSig verifies an honestly-signed signature
// (which always uses padding < 1000) still verifies after the bound is added.
func TestRabinPaddingBound_AcceptsHonestSig(t *testing.T) {
	msg := []byte("attack at dawn")

	sigInt, padInt := RabinSign(msg, RabinTestP(), RabinTestQ())
	sigBytes := bigIntToLEBytes(sigInt)
	padBytes := bigIntToLEBytes(padInt)

	if !rabinVerifyImpl(msg, sigBytes, padBytes, []byte(RabinTestKeyN)) {
		t.Fatalf("honest signature rejected: sig=%s padding=%s", sigInt, padInt)
	}
}

// TestRabinSigRange_RejectsNonCanonicalSig (N-380, F-368 follow-up): the
// on-chain script asserts sig < n before squaring, so sig + k*n aborts there.
// The off-chain verifier must reject the same encodings.
//
// Proves: the canonical sig and the second root n - sig are accepted; sig + n
// and sig + 2n (same padding) are rejected. Does not prove the verdict equals
// the consensus interpreter's (conformance/negatives/f368 does that).
func TestRabinSigRange_RejectsNonCanonicalSig(t *testing.T) {
	msg := []byte("attack at dawn")
	n := leBytesToBigInt([]byte(RabinTestKeyN))
	sigInt, padInt := RabinSign(msg, RabinTestP(), RabinTestQ())
	padBytes := bigIntToLEBytes(padInt)
	pk := []byte(RabinTestKeyN)

	canonical := []*big.Int{sigInt, new(big.Int).Sub(n, sigInt)}
	for _, s := range canonical {
		if !rabinVerifyImpl(msg, bigIntToLEBytes(s), padBytes, pk) {
			t.Fatalf("canonical sig %s rejected", s)
		}
	}
	for k := int64(1); k <= 2; k++ {
		s := new(big.Int).Add(sigInt, new(big.Int).Mul(n, big.NewInt(k)))
		if rabinVerifyImpl(msg, bigIntToLEBytes(s), padBytes, pk) {
			t.Fatalf("non-canonical sig + %d*n accepted", k)
		}
	}
}
