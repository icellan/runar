package runar

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSha256CompressBlock_ABC(t *testing.T) {
	// SHA-256("abc") = ba7816bf...
	// One block: "abc" + padding
	block := [64]byte{}
	block[0] = 0x61 // 'a'
	block[1] = 0x62 // 'b'
	block[2] = 0x63 // 'c'
	block[3] = 0x80 // padding
	// bit length = 24 = 0x18, goes in last byte
	block[63] = 0x18

	result := Sha256CompressBlock(sha256Init, block)
	got := stateToHex(result)
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("SHA-256(\"abc\") mismatch\n  got:  %s\n  want: %s", got, want)
	}
}

func TestSha256CompressBlock_MatchesStdlib(t *testing.T) {
	// Compress a known message and verify against crypto/sha256
	message := []byte("Hello, Bitcoin SV!")
	padded := sha256Pad(message)
	if len(padded)%64 != 0 {
		t.Fatalf("padded length %d is not a multiple of 64", len(padded))
	}

	state := sha256Init
	totalBlocks := len(padded) / 64
	for i := 0; i < totalBlocks; i++ {
		var block [64]byte
		copy(block[:], padded[i*64:(i+1)*64])
		state = Sha256CompressBlock(state, block)
	}

	// Convert state to bytes
	var hashBytes [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(hashBytes[i*4:], state[i])
	}

	expected := sha256.Sum256(message)
	if hashBytes != expected {
		t.Errorf("SHA-256 mismatch\n  got:  %x\n  want: %x", hashBytes, expected)
	}
}

func TestPartialSha256_Basic(t *testing.T) {
	// 200-byte tx: padded to 256 bytes (4 blocks), pre-hashed = 2
	rawHex := strings.Repeat("ab", 200)
	result, err := ComputePartialSha256ForInductive(rawHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.ParentHashState) != 64 {
		t.Errorf("ParentHashState length = %d, want 64", len(result.ParentHashState))
	}
	if len(result.ParentTailBlock1) != 128 {
		t.Errorf("ParentTailBlock1 length = %d, want 128", len(result.ParentTailBlock1))
	}
	if len(result.ParentTailBlock2) != 128 {
		t.Errorf("ParentTailBlock2 length = %d, want 128", len(result.ParentTailBlock2))
	}
	// raw_tail_len = 200 - 2*64 = 72
	if result.ParentRawTailLen != 72 {
		t.Errorf("ParentRawTailLen = %d, want 72", result.ParentRawTailLen)
	}
}

func TestPartialSha256_SmallTx(t *testing.T) {
	// 100-byte tx: padded to 128 bytes (2 blocks), pre-hashed = 0, state = init
	rawHex := strings.Repeat("cd", 100)
	result, err := ComputePartialSha256ForInductive(rawHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	initHex := stateToHex(sha256Init)
	if result.ParentHashState != initHex {
		t.Errorf("ParentHashState = %s, want %s (SHA-256 init)", result.ParentHashState, initHex)
	}
	if result.ParentRawTailLen != 100 {
		t.Errorf("ParentRawTailLen = %d, want 100", result.ParentRawTailLen)
	}
}

func TestPartialSha256_ReconstructsFullHash(t *testing.T) {
	// Verify that compressing the tail blocks on top of the partial state
	// produces the same result as hashing the full message.
	rawHex := strings.Repeat("de", 300)
	rawBytes, _ := hex.DecodeString(rawHex)

	result, err := ComputePartialSha256ForInductive(rawHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Reconstruct: start from partial state, compress tail blocks
	stateBytes, _ := hex.DecodeString(result.ParentHashState)
	var state [8]uint32
	for i := 0; i < 8; i++ {
		state[i] = binary.BigEndian.Uint32(stateBytes[i*4 : i*4+4])
	}

	block1Bytes, _ := hex.DecodeString(result.ParentTailBlock1)
	var block1 [64]byte
	copy(block1[:], block1Bytes)
	state = Sha256CompressBlock(state, block1)

	block2Bytes, _ := hex.DecodeString(result.ParentTailBlock2)
	var block2 [64]byte
	copy(block2[:], block2Bytes)
	state = Sha256CompressBlock(state, block2)

	var reconstructed [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(reconstructed[i*4:], state[i])
	}

	expected := sha256.Sum256(rawBytes)
	if reconstructed != expected {
		t.Errorf("Reconstructed hash mismatch\n  got:  %x\n  want: %x", reconstructed, expected)
	}
}

func TestPartialSha256_InvalidHex(t *testing.T) {
	_, err := ComputePartialSha256ForInductive("not-valid-hex")
	if err == nil {
		t.Error("expected error for invalid hex, got nil")
	}
}
