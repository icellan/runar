package runar

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Cross-language reference vectors for the Rúnar BLAKE3 single-block
// compression with hardcoded blockLen=64, counter=0, flags=11
// (CHUNK_START | CHUNK_END | ROOT). These exact hex strings are pinned in the
// Python and (forthcoming) TS / Rust runtimes — any divergence is a
// cross-compiler regression.
var blake3HashRefVectors = []struct {
	name string
	in   []byte
	want string
}{
	{"empty", []byte{}, "7669004d96866a6330a609d9ad1a08a4f8507c4d04eefd1a50f00b02556aab86"},
	{"abc", []byte("abc"), "6f9871b5d6e80fc882e7bb57857f8b279cdc229664eab9382d2838dbf7d8a20d"},
	{"hello world", []byte("hello world"), "47d3d7048c7ed47c986773cc1eefaa0b356bec676dd62cca3269a086999d65fc"},
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
	// blake3Hash(msg) must equal Blake3Compress(IV, zero-pad(msg, 64)).
	// This is the contract that the on-chain codegen implements.
	cases := [][]byte{[]byte{}, []byte("abc"), []byte("hello world"), []byte{0x19, 0x76, 0xa9, 0x14}}
	for _, msg := range cases {
		padded := make([]byte, 64)
		copy(padded, msg)
		direct := Blake3Compress(ByteString(blake3IVBytes()), ByteString(padded))
		viaHash := Blake3Hash(ByteString(msg))
		if !bytes.Equal([]byte(direct), []byte(viaHash)) {
			t.Fatalf("Blake3Hash(%x) != Blake3Compress(IV, pad(%x))", msg, msg)
		}
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

// blake3IVBytes returns the BLAKE3 IV as 32 big-endian bytes (8 u32 words).
// Mirrors the constant used inside the runtime; duplicated here so the test
// stays self-contained and catches any IV-byte-order regression.
func blake3IVBytes() []byte {
	words := [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	out := make([]byte, 32)
	for i, w := range words {
		out[i*4+0] = byte(w >> 24)
		out[i*4+1] = byte(w >> 16)
		out[i*4+2] = byte(w >> 8)
		out[i*4+3] = byte(w)
	}
	return out
}
