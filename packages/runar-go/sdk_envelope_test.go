package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ---------------------------------------------------------------------------
// testSigner — wraps an ec.PrivateKey and implements EnvelopeSigner. Uses raw
// ECDSA over the supplied digest (matching the wire-protocol's verify path).
// ---------------------------------------------------------------------------

type testSigner struct {
	priv *ec.PrivateKey
}

func (s *testSigner) SignHash(digest []byte) ([]byte, error) {
	sig, err := s.priv.Sign(digest) // Go bsv-sdk PrivateKey.Sign signs the digest raw
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func (s *testSigner) PublicKey() (string, error) {
	return hex.EncodeToString(s.priv.PubKey().Compressed()), nil
}

func newAliceSigner(t *testing.T) *testSigner {
	t.Helper()
	priv, _ := ec.PrivateKeyFromBytes([]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	})
	return &testSigner{priv: priv}
}

func newBobSigner(t *testing.T) *testSigner {
	t.Helper()
	priv, _ := ec.PrivateKeyFromBytes([]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
	})
	return &testSigner{priv: priv}
}

// ---------------------------------------------------------------------------
// CanonicalJSON
// ---------------------------------------------------------------------------

func TestCanonicalJSON_InsertionOrderIndependent(t *testing.T) {
	a, err := CanonicalJSON(map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := CanonicalJSON(map[string]any{"b": 2, "a": 1})
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a != b {
		t.Errorf("canonical JSON should be order-independent: %q vs %q", a, b)
	}
	if a != `{"a":1,"b":2}` {
		t.Errorf("unexpected canonical form: %q", a)
	}
}

func TestCanonicalJSON_NestedAndPrimitives(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{
		"outer": map[string]any{"z": 1, "a": []any{3, 2, 1}},
		"list":  []any{map[string]any{"y": 1, "x": 2}},
		"n":     nil,
		"b":     true,
		"s":     "hi",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := `{"b":true,"list":[{"x":2,"y":1}],"n":null,"outer":{"a":[3,2,1],"z":1},"s":"hi"}`
	if got != want {
		t.Errorf("\n got: %s\nwant: %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Round-trip + rejection ladder
// ---------------------------------------------------------------------------

func TestSignVerify_RoundTrip(t *testing.T) {
	signer := newAliceSigner(t)
	env, err := SignEnvelope(SignEnvelopeOpts{
		Data:   map[string]any{"kind": "hello", "n": int64(7)},
		Signer: signer,
		NowMs:  1_000_000_000_000,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1_000_000_000_500})
	if !got.OK {
		t.Fatalf("verify failed: reason=%s", got.Reason)
	}
	if v, _ := got.Data["kind"].(string); v != "hello" {
		t.Errorf("data.kind = %v, want hello", got.Data["kind"])
	}
}

func TestVerify_MissingFields(t *testing.T) {
	signer := newAliceSigner(t)
	env, _ := SignEnvelope(SignEnvelopeOpts{Data: map[string]any{"ok": int64(1)}, Signer: signer, NowMs: 1_000_000_000_000})
	env.Sig = ""
	got := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1_000_000_000_500})
	if got.OK || got.Reason != ReasonMissingFields {
		t.Errorf("want missing-fields, got OK=%v reason=%s", got.OK, got.Reason)
	}
}

func TestVerify_Expired(t *testing.T) {
	signer := newAliceSigner(t)
	env, _ := SignEnvelope(SignEnvelopeOpts{Data: map[string]any{"ok": int64(1)}, Signer: signer, NowMs: 1_000_000_000_000})
	// Verify with a "now" far past the envelope's expiry.
	got := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1_000_000_000_000 + 1_000_000})
	if got.OK || got.Reason != ReasonExpired {
		t.Errorf("want expired, got OK=%v reason=%s", got.OK, got.Reason)
	}
}

func TestVerify_BadJSON(t *testing.T) {
	signer := newAliceSigner(t)
	env, _ := SignEnvelope(SignEnvelopeOpts{Data: map[string]any{"ok": int64(1)}, Signer: signer, NowMs: 1_000_000_000_000})
	env.Payload = "not json{"
	got := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1_000_000_000_500})
	if got.OK || got.Reason != ReasonBadJSON {
		t.Errorf("want bad-json, got OK=%v reason=%s", got.OK, got.Reason)
	}
}

func TestVerify_EnvelopeMismatch(t *testing.T) {
	signer := newAliceSigner(t)
	env, _ := SignEnvelope(SignEnvelopeOpts{Data: map[string]any{"ok": int64(1)}, Signer: signer, NowMs: 1_000_000_000_000})
	env.Nonce = env.Nonce + 1
	got := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1_000_000_000_500})
	if got.OK || got.Reason != ReasonEnvelopeMismatch {
		t.Errorf("want envelope-mismatch, got OK=%v reason=%s", got.OK, got.Reason)
	}
	if got.Data == nil {
		t.Error("data should be populated on envelope-mismatch")
	}
}

func TestVerify_BadSig(t *testing.T) {
	signer := newAliceSigner(t)
	env, _ := SignEnvelope(SignEnvelopeOpts{Data: map[string]any{"ok": int64(1)}, Signer: signer, NowMs: 1_000_000_000_000})
	// Flip a hex char in the middle (avoid DER-tag corruption).
	mid := len(env.Sig) / 2
	swap := byte('1')
	if env.Sig[mid] == '1' {
		swap = '2'
	}
	env.Sig = env.Sig[:mid] + string(swap) + env.Sig[mid+1:]
	got := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, NowMs: 1_000_000_000_500})
	if got.OK || got.Reason != ReasonBadSig {
		t.Errorf("want bad-sig, got OK=%v reason=%s", got.OK, got.Reason)
	}
}

func TestVerify_PubkeyNotAllowed(t *testing.T) {
	alice := newAliceSigner(t)
	bob := newBobSigner(t)
	env, _ := SignEnvelope(SignEnvelopeOpts{Data: map[string]any{"ok": int64(1)}, Signer: alice, NowMs: 1_000_000_000_000})
	bobPub, _ := bob.PublicKey()
	got := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, ExpectedKeys: []string{bobPub}, NowMs: 1_000_000_000_500})
	if got.OK || got.Reason != ReasonPubkeyNotAllowed {
		t.Errorf("want pubkey-not-allowed, got OK=%v reason=%s", got.OK, got.Reason)
	}
}

func TestVerify_PubkeyAllowed(t *testing.T) {
	signer := newAliceSigner(t)
	env, _ := SignEnvelope(SignEnvelopeOpts{Data: map[string]any{"ok": int64(1)}, Signer: signer, NowMs: 1_000_000_000_000})
	got := VerifyEnvelope(VerifyEnvelopeOpts{Envelope: env, ExpectedKeys: []string{env.Pubkey}, NowMs: 1_000_000_000_500})
	if !got.OK {
		t.Errorf("expected OK with pubkey in allowlist; got reason=%s", got.Reason)
	}
}

// Sanity check: the digest signed by SignEnvelope must equal sha256(payload).
func TestSignEnvelope_DigestMatchesPayload(t *testing.T) {
	signer := newAliceSigner(t)
	env, _ := SignEnvelope(SignEnvelopeOpts{Data: map[string]any{"k": int64(1)}, Signer: signer, NowMs: 1_000_000_000_000})
	expectedDigest := sha256.Sum256([]byte(env.Payload))
	sigBytes, _ := hex.DecodeString(env.Sig)
	pkBytes, _ := hex.DecodeString(env.Pubkey)
	pubKey, _ := ec.ParsePubKey(pkBytes)
	sig, _ := ec.FromDER(sigBytes)
	if !sig.Verify(expectedDigest[:], pubKey) {
		t.Error("signature did not verify against sha256(payload)")
	}
}
