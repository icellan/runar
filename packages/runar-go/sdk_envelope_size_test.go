package runar

import (
	"strings"
	"testing"
)

func TestVerifyEnvelope_RejectsOversizedPayload(t *testing.T) {
	// Payload one byte over MaxEnvelopePayloadBytes. Other fields kept
	// minimal — the size guard fires first, before missing-fields /
	// expired / bad-json / bad-sig.
	env := SignedEnvelope{
		Payload:   strings.Repeat("x", MaxEnvelopePayloadBytes+1),
		Sig:       "00",
		Pubkey:    "00",
		Nonce:     1,
		ExpiresAt: 9_999_999_999_999,
	}

	res := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1})
	if res.OK {
		t.Fatal("expected verify to fail")
	}
	if res.Reason != ReasonTooLarge {
		t.Fatalf("expected reason=%q, got %q", ReasonTooLarge, res.Reason)
	}
}

func TestVerifyEnvelope_RejectsOversizedSig(t *testing.T) {
	env := SignedEnvelope{
		Payload:   `{"nonce":1,"expiresAt":9999999999999}`,
		Sig:       strings.Repeat("a", MaxEnvelopeFieldBytes+1),
		Pubkey:    "00",
		Nonce:     1,
		ExpiresAt: 9_999_999_999_999,
	}

	res := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1})
	if res.OK {
		t.Fatal("expected verify to fail")
	}
	if res.Reason != ReasonTooLarge {
		t.Fatalf("expected reason=%q, got %q", ReasonTooLarge, res.Reason)
	}
}

func TestVerifyEnvelope_NormalSizedEnvelopeStillRunsThrough(t *testing.T) {
	// Modest-sized payload must NOT trip the size guard. We expect
	// bad-sig (or similar) downstream — the assertion is only that we
	// do NOT get too-large.
	env := SignedEnvelope{
		Payload:   `{"nonce":1,"expiresAt":9999999999999}`,
		Sig:       "deadbeef",
		Pubkey:    "deadbeef",
		Nonce:     1,
		ExpiresAt: 9_999_999_999_999,
	}

	res := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1})
	if res.Reason == ReasonTooLarge {
		t.Fatalf("size guard incorrectly tripped on normal-sized envelope: %v", res.Reason)
	}
}
