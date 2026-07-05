package runar

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Cross-language reference vectors for the Rúnar standard BLAKE3 single-block
// hash (little-endian, real message length as block_len, counter=0, flags=11 =
// CHUNK_START | CHUNK_END | ROOT). These are the official BLAKE3 digests and
// are pinned across the TS / Rust / Python / … runtimes — any divergence is a
// cross-compiler regression.
var blake3HashRefVectors = []struct {
	name string
	in   []byte
	want string
}{
	{"empty", []byte{}, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
	{"abc", []byte("abc"), "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"},
	{"hello world", []byte("hello world"), "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"},
}

func TestBlake3Hash_MatchesCrossLanguageReference(t *testing.T) {
	for _, tc := range blake3HashRefVectors {
		t.Run(tc.name, func(t *testing.T) {
			got := Blake3Hash(ByteString(tc.in))
			gotHex := hex.EncodeToString([]byte(got))
			if gotHex != tc.want {
				t.Fatalf("Blake3Hash(%q) = %s, want %s", string(tc.in), gotHex, tc.want)
			}
		})
	}
}

func TestBlake3Compress_NotZeroStub(t *testing.T) {
	// Guards against regression back to the all-zero stub.
	out := Blake3Compress(ByteString(make([]byte, 32)), ByteString(make([]byte, 64)))
	if len(out) != 32 {
		t.Fatalf("Blake3Compress output length = %d, want 32", len(out))
	}
	if bytes.Equal([]byte(out), make([]byte, 32)) {
		t.Fatalf("Blake3Compress(0,0) returned 32 zero bytes — still a stub")
	}
}

func TestBlake3Hash_EquivalentToCompressionWithIV(t *testing.T) {
	// For a full 64-byte message, Blake3Hash(msg) == Blake3Compress(IV, msg):
	// both use block_len = 64. For shorter messages the block_len differs (the
	// hash uses the real length), so the equivalence holds ONLY at exactly 64
	// bytes — that separation is the BUG-101 fix.
	msg := make([]byte, 64)
	for i := range msg {
		msg[i] = byte(i)
	}
	direct := Blake3Compress(ByteString(blake3IVBytes()), ByteString(msg))
	viaHash := Blake3Hash(ByteString(msg))
	if !bytes.Equal([]byte(direct), []byte(viaHash)) {
		t.Fatalf("Blake3Hash(64B) = %x != Blake3Compress(IV, 64B) = %x", viaHash, direct)
	}
}

func TestBlake3Compress_Determinism(t *testing.T) {
	cv := make([]byte, 32)
	for i := range cv {
		cv[i] = byte(i)
	}
	block := make([]byte, 64)
	for i := range block {
		block[i] = byte(i)
	}
	a := Blake3Compress(ByteString(cv), ByteString(block))
	b := Blake3Compress(ByteString(cv), ByteString(block))
	if !bytes.Equal([]byte(a), []byte(b)) {
		t.Fatalf("Blake3Compress non-deterministic: %x vs %x", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("Blake3Compress output length = %d, want 32", len(a))
	}
}

// blake3IVBytes returns the BLAKE3 IV as 32 little-endian bytes (8 u32 words).
// Mirrors the constant used inside the runtime; duplicated here so the test
// stays self-contained and catches any IV-byte-order regression.
func blake3IVBytes() []byte {
	words := [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	out := make([]byte, 32)
	for i, w := range words {
		out[i*4+0] = byte(w)
		out[i*4+1] = byte(w >> 8)
		out[i*4+2] = byte(w >> 16)
		out[i*4+3] = byte(w >> 24)
	}
	return out
}
