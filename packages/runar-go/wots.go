// WOTS+ (Winternitz One-Time Signature) reference implementation.
//
// RFC 8391 compatible with tweakable hash function F(pubSeed, ADRS, M).
//
// Parameters: w=16, n=32 (SHA-256).
//   len1 = 64  (message digits: 256 bits / 4 bits per digit)
//   len2 = 3   (checksum digits)
//   len  = 67  (total hash chains)
//
// Signature: 67 x 32 bytes = 2,144 bytes.
// Public key: 64 bytes (pubSeed(32) || pkRoot(32)).
package runar

import (
	"crypto/rand"
	"crypto/sha256"
)

const (
	wotsW    = 16
	wotsN    = 32
	wotsLogW = 4
	wotsLen1 = 64 // ceil(8*N / LOG_W) = 256/4
	wotsLen2 = 3  // floor(log2(LEN1*(W-1)) / LOG_W) + 1
	wotsLen  = wotsLen1 + wotsLen2 // 67
)

// WOTSKeyPair holds a WOTS+ keypair.
type WOTSKeyPair struct {
	SK      [][]byte // 67 secret key elements, each 32 bytes
	PK      []byte   // 64-byte public key: pubSeed(32) || pkRoot(32)
	PubSeed []byte   // 32-byte public seed (first 32 bytes of PK)
}

// Tweakable hash F(pubSeed, chainIdx, stepIdx, msg).
func wotsF(pubSeed []byte, chainIdx, stepIdx int, msg []byte) []byte {
	input := make([]byte, wotsN+2+len(msg))
	copy(input, pubSeed)
	input[wotsN] = byte(chainIdx)
	input[wotsN+1] = byte(stepIdx)
	copy(input[wotsN+2:], msg)
	h := sha256.Sum256(input)
	return h[:]
}

// chain iterates the tweakable hash function.
func wotsChain(x []byte, startStep, steps int, pubSeed []byte, chainIdx int) []byte {
	current := make([]byte, len(x))
	copy(current, x)
	for j := startStep; j < startStep+steps; j++ {
		current = wotsF(pubSeed, chainIdx, j, current)
	}
	return current
}

// extractDigits extracts base-16 digits from a 32-byte hash.
func wotsExtractDigits(hash []byte) []int {
	digits := make([]int, 0, wotsLen1)
	for _, b := range hash {
		digits = append(digits, int((b>>4)&0x0f))
		digits = append(digits, int(b&0x0f))
	}
	return digits
}

// checksumDigits computes WOTS+ checksum digits.
func wotsChecksumDigits(msgDigits []int) []int {
	sum := 0
	for _, d := range msgDigits {
		sum += (wotsW - 1) - d
	}
	digits := make([]int, wotsLen2)
	remaining := sum
	for i := wotsLen2 - 1; i >= 0; i-- {
		digits[i] = remaining % wotsW
		remaining /= wotsW
	}
	return digits
}

// allDigits returns all 67 digits: 64 message + 3 checksum.
func wotsAllDigits(msgHash []byte) []int {
	msg := wotsExtractDigits(msgHash)
	csum := wotsChecksumDigits(msg)
	return append(msg, csum...)
}

// WotsKeygen generates a WOTS+ keypair.
// If seed is nil, random keys are generated. If pubSeed is nil, a random one is used.
func WotsKeygen(seed, pubSeed []byte) WOTSKeyPair {
	ps := pubSeed
	if ps == nil {
		ps = make([]byte, wotsN)
		rand.Read(ps)
	}

	sk := make([][]byte, wotsLen)
	for i := 0; i < wotsLen; i++ {
		if seed != nil {
			buf := make([]byte, wotsN+4)
			copy(buf, seed)
			buf[wotsN] = byte(i >> 24)
			buf[wotsN+1] = byte(i >> 16)
			buf[wotsN+2] = byte(i >> 8)
			buf[wotsN+3] = byte(i)
			h := sha256.Sum256(buf)
			sk[i] = h[:]
		} else {
			sk[i] = make([]byte, wotsN)
			rand.Read(sk[i])
		}
	}

	// Compute chain endpoints
	concat := make([]byte, wotsLen*wotsN)
	for i := 0; i < wotsLen; i++ {
		endpoint := wotsChain(sk[i], 0, wotsW-1, ps, i)
		copy(concat[i*wotsN:], endpoint)
	}

	pkRoot := sha256.Sum256(concat)

	pk := make([]byte, 2*wotsN)
	copy(pk, ps)
	copy(pk[wotsN:], pkRoot[:])

	return WOTSKeyPair{SK: sk, PK: pk, PubSeed: ps}
}

// WotsSign signs a message with WOTS+.
func WotsSign(msg []byte, sk [][]byte, pubSeed []byte) []byte {
	msgHash := sha256.Sum256(msg)
	digits := wotsAllDigits(msgHash[:])

	sig := make([]byte, wotsLen*wotsN)
	for i := 0; i < wotsLen; i++ {
		element := wotsChain(sk[i], 0, digits[i], pubSeed, i)
		copy(sig[i*wotsN:], element)
	}
	return sig
}

// wotsVerifyImpl verifies a WOTS+ signature.
func wotsVerifyImpl(msg, sig, pk []byte) bool {
	if len(sig) != wotsLen*wotsN {
		return false
	}
	if len(pk) != 2*wotsN {
		return false
	}

	pubSeed := pk[:wotsN]
	pkRoot := pk[wotsN:]

	msgHash := sha256.Sum256(msg)
	digits := wotsAllDigits(msgHash[:])

	concat := make([]byte, wotsLen*wotsN)
	for i := 0; i < wotsLen; i++ {
		sigElement := sig[i*wotsN : (i+1)*wotsN]
		remaining := (wotsW - 1) - digits[i]
		endpoint := wotsChain(sigElement, digits[i], remaining, pubSeed, i)
		copy(concat[i*wotsN:], endpoint)
	}

	computedRoot := sha256.Sum256(concat)
	if len(computedRoot) != len(pkRoot) {
		return false
	}
	for i := range pkRoot {
		if computedRoot[i] != pkRoot[i] {
			return false
		}
	}
	return true
}
