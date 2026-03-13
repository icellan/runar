package runar

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
)

// ---------------------------------------------------------------------------
// sha256_compress.go — SHA-256 compression utility for inductive contracts
// ---------------------------------------------------------------------------
//
// Provides a pure SHA-256 compression function and a helper that computes
// partial SHA-256 state for inductive contract parent-tx verification.
// The on-chain script receives only the last 3 blocks and the intermediate
// hash state, avoiding the need to push the full raw parent tx.
// ---------------------------------------------------------------------------

// sha256K contains the 64 round constants (FIPS 180-4 Section 4.2.2).
// Derived from the fractional parts of the cube roots of the first 64 primes.
var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// sha256Init contains the 8 initial hash values (FIPS 180-4 Section 5.3.3).
// Derived from the fractional parts of the square roots of the first 8 primes.
var sha256Init = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// Sha256CompressBlock applies the SHA-256 compression function for one 64-byte
// block. Takes an 8-word intermediate hash state and a 64-byte message block,
// applies 64 rounds of compression, and returns the updated 8-word state.
func Sha256CompressBlock(state [8]uint32, block [64]byte) [8]uint32 {
	rotr := func(x uint32, n int) uint32 {
		return bits.RotateLeft32(x, -n)
	}

	// Expand 16 message words to 64
	var W [64]uint32
	for i := 0; i < 16; i++ {
		W[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
	}
	for t := 16; t < 64; t++ {
		s0 := rotr(W[t-15], 7) ^ rotr(W[t-15], 18) ^ (W[t-15] >> 3)
		s1 := rotr(W[t-2], 17) ^ rotr(W[t-2], 19) ^ (W[t-2] >> 10)
		W[t] = s1 + W[t-7] + s0 + W[t-16]
	}

	// Initialize working variables
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]

	// 64 rounds of compression
	for t := 0; t < 64; t++ {
		S1 := rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
		ch := (e & f) ^ (^e & g)
		T1 := h + S1 + ch + sha256K[t] + W[t]
		S0 := rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		T2 := S0 + maj
		h = g
		g = f
		f = e
		e = d + T1
		d = c
		c = b
		b = a
		a = T1 + T2
	}

	// Add compressed chunk to current hash state
	return [8]uint32{
		a + state[0],
		b + state[1],
		c + state[2],
		d + state[3],
		e + state[4],
		f + state[5],
		g + state[6],
		h + state[7],
	}
}

// PartialSha256Result holds the 5 components needed by the on-chain inductive
// contract script to complete the double-SHA256 of the parent transaction.
type PartialSha256Result struct {
	// ParentHashState is the 32-byte hex intermediate SHA-256 state after
	// compressing all blocks except the last 3.
	ParentHashState string
	// ParentTailBlock1 is the 64-byte hex third-to-last block.
	ParentTailBlock1 string
	// ParentTailBlock2 is the 64-byte hex second-to-last block.
	ParentTailBlock2 string
	// ParentTailBlock3 is the 64-byte hex last block (contains padding).
	ParentTailBlock3 string
	// ParentRawTailLen is the number of raw (unpadded) tx bytes in the
	// three tail blocks.
	ParentRawTailLen int
}

// sha256Pad applies SHA-256 padding to a message (FIPS 180-4 Section 5.1.1).
// Appends 0x80, zero-pads to 56 mod 64, then appends 8-byte big-endian bit length.
func sha256Pad(message []byte) []byte {
	msgLen := len(message)
	bitLen := uint64(msgLen) * 8

	// Calculate padded length
	paddedLen := msgLen + 1
	for paddedLen%64 != 56 {
		paddedLen++
	}
	paddedLen += 8

	padded := make([]byte, paddedLen)
	copy(padded, message)
	padded[msgLen] = 0x80

	// Append 8-byte big-endian bit length
	binary.BigEndian.PutUint64(padded[paddedLen-8:], bitLen)

	return padded
}

// stateToHex converts an 8-word state to a 64-char hex string.
func stateToHex(state [8]uint32) string {
	var buf [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(buf[i*4:], state[i])
	}
	return hex.EncodeToString(buf[:])
}

// ComputePartialSha256ForInductive computes the partial SHA-256 state for an
// inductive contract's parent transaction.
//
// Instead of pushing the full raw parent tx on-chain, we pre-compute the
// SHA-256 state up to (but not including) the last 3 blocks. The on-chain
// script receives:
//   - The intermediate hash state (32 bytes)
//   - The three tail blocks (64 bytes each)
//   - The raw tail length (to locate fields within the tail)
//
// It then completes the double-SHA256 to derive the parent txid and
// verifies it against the outpoint in the sighash preimage.
func ComputePartialSha256ForInductive(rawTxHex string) (*PartialSha256Result, error) {
	rawBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return nil, fmt.Errorf("ComputePartialSha256ForInductive: invalid hex: %w", err)
	}

	padded := sha256Pad(rawBytes)
	totalBlocks := len(padded) / 64

	if totalBlocks < 3 {
		return nil, fmt.Errorf("ComputePartialSha256ForInductive: padded message has %d blocks, need at least 3", totalBlocks)
	}

	// Raw tail length = total raw bytes minus the bytes in pre-hashed blocks
	rawTailLen := len(rawBytes) - (totalBlocks-3)*64
	if rawTailLen < 115 {
		return nil, fmt.Errorf("ComputePartialSha256ForInductive: rawTailLen %d is less than 115 (minimum for inductive field extraction)", rawTailLen)
	}

	// Compress all blocks except the last 3 to get intermediate state
	state := sha256Init
	preHashedBlocks := totalBlocks - 3
	for i := 0; i < preHashedBlocks; i++ {
		var block [64]byte
		copy(block[:], padded[i*64:(i+1)*64])
		state = Sha256CompressBlock(state, block)
	}

	tailBlock1 := padded[preHashedBlocks*64 : (preHashedBlocks+1)*64]
	tailBlock2 := padded[(preHashedBlocks+1)*64 : (preHashedBlocks+2)*64]
	tailBlock3 := padded[(preHashedBlocks+2)*64 : (preHashedBlocks+3)*64]

	return &PartialSha256Result{
		ParentHashState:  stateToHex(state),
		ParentTailBlock1: hex.EncodeToString(tailBlock1),
		ParentTailBlock2: hex.EncodeToString(tailBlock2),
		ParentTailBlock3: hex.EncodeToString(tailBlock3),
		ParentRawTailLen: rawTailLen,
	}, nil
}
