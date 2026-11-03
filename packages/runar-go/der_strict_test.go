package runar

// F-242 (CL-BUG-160): strict DER (BIP66) for ECDSA signatures.
//
// conformance/sdk-der/vectors.json is the cross-tier vector set: every
// ok=false entry re-encodes a valid signature's (r, s), so only the encoding
// can make it fail. go-sdk's ec.ParseDERSignature reads the SEQUENCE length
// and then ignores any bytes after it, so a signature followed by two or more
// junk bytes verified as valid here (one trailing byte is the sighash type and
// is stripped by the caller).
//
// Proves: anfVerifyEcdsa (the ANF interpreter's real-crypto checkSig, which
// is ecdsaVerify behind the sighash-byte strip) reaches the fixture verdict on
// every vector, and CheckSig does on the ones signed over TestMessageDigest.
// Does not prove the envelope path (sdk_envelope_interop_test.go replays the
// fixture's der-* rejection vectors) or anything about curve arithmetic.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type derVector struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Sig    string `json:"sig"`
	OK     bool   `json:"ok"`
}

func loadDerVectors(t *testing.T) (string, []derVector) {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-der", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f struct {
		Pubkey  string      `json:"pubkey"`
		Vectors []derVector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return f.Pubkey, f.Vectors
}

func TestStrictDER_AnfVerifyEcdsa(t *testing.T) {
	pub, vectors := loadDerVectors(t)
	for _, v := range vectors {
		d, _ := hex.DecodeString(v.Digest)
		if got := anfVerifyEcdsa(v.Sig, pub, d); got != v.OK {
			t.Errorf("%s: anfVerifyEcdsa = %v, want %v", v.ID, got, v.OK)
		}
	}
}

func TestStrictDER_CheckSig(t *testing.T) {
	pub, vectors := loadDerVectors(t)
	pk, _ := hex.DecodeString(pub)
	n := 0
	for _, v := range vectors {
		if v.Digest != hex.EncodeToString(TestMessageDigest[:]) {
			continue
		}
		n++
		sig, _ := hex.DecodeString(v.Sig)
		if got := CheckSig(Sig(sig), PubKey(pk)); got != v.OK {
			t.Errorf("%s: CheckSig = %v, want %v", v.ID, got, v.OK)
		}
	}
	if n == 0 {
		t.Fatal("no vectors over TestMessageDigest")
	}
}
