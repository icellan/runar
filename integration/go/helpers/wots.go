package helpers

import (
	"crypto/sha256"
	"encoding/hex"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// WOTS+ constants (w=16, n=32)
const (
	WotsW    = 16
	WotsN    = 32
	WotsLen1 = 64 // ceil(8*N / log2(W))
	WotsLen2 = 3  // floor(log2(Len1*(W-1)) / log2(W)) + 1
	WotsLen  = 67 // Len1 + Len2
)

type WOTSKeyPair struct {
	SK      [][]byte
	PK      []byte // 64 bytes: pubSeed(32) || pkRoot(32)
	PubSeed []byte
}

func wotsSha256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func wotsF(pubSeed []byte, chainIdx, stepIdx int, msg []byte) []byte {
	input := make([]byte, WotsN+2+len(msg))
	copy(input, pubSeed)
	input[WotsN] = byte(chainIdx)
	input[WotsN+1] = byte(stepIdx)
	copy(input[WotsN+2:], msg)
	return wotsSha256(input)
}

func wotsChain(x []byte, startStep, steps int, pubSeed []byte, chainIdx int) []byte {
	current := make([]byte, len(x))
	copy(current, x)
	for j := startStep; j < startStep+steps; j++ {
		current = wotsF(pubSeed, chainIdx, j, current)
	}
	return current
}

func wotsExtractDigits(hash []byte) []int {
	digits := make([]int, 0, WotsLen1)
	for _, b := range hash {
		digits = append(digits, int((b>>4)&0x0f))
		digits = append(digits, int(b&0x0f))
	}
	return digits
}

func wotsChecksumDigits(msgDigits []int) []int {
	sum := 0
	for _, d := range msgDigits {
		sum += (WotsW - 1) - d
	}
	digits := make([]int, WotsLen2)
	remaining := sum
	for i := WotsLen2 - 1; i >= 0; i-- {
		digits[i] = remaining % WotsW
		remaining /= WotsW
	}
	return digits
}

func wotsAllDigits(msgHash []byte) []int {
	msg := wotsExtractDigits(msgHash)
	csum := wotsChecksumDigits(msg)
	return append(msg, csum...)
}

// WOTSKeygen generates a WOTS+ keypair.
func WOTSKeygen(seed, pubSeed []byte) WOTSKeyPair {
	sk := make([][]byte, WotsLen)
	for i := 0; i < WotsLen; i++ {
		buf := make([]byte, WotsN+4)
		copy(buf, seed)
		buf[WotsN] = byte((i >> 24) & 0xff)
		buf[WotsN+1] = byte((i >> 16) & 0xff)
		buf[WotsN+2] = byte((i >> 8) & 0xff)
		buf[WotsN+3] = byte(i & 0xff)
		sk[i] = wotsSha256(buf)
	}

	endpoints := make([][]byte, WotsLen)
	for i := 0; i < WotsLen; i++ {
		endpoints[i] = wotsChain(sk[i], 0, WotsW-1, pubSeed, i)
	}

	concat := make([]byte, WotsLen*WotsN)
	for i := 0; i < WotsLen; i++ {
		copy(concat[i*WotsN:], endpoints[i])
	}
	pkRoot := wotsSha256(concat)

	pk := make([]byte, 2*WotsN)
	copy(pk, pubSeed)
	copy(pk[WotsN:], pkRoot)

	return WOTSKeyPair{SK: sk, PK: pk, PubSeed: pubSeed}
}

// WOTSSign signs a message with WOTS+.
func WOTSSign(msg []byte, sk [][]byte, pubSeed []byte) []byte {
	msgHash := wotsSha256(msg)
	digits := wotsAllDigits(msgHash)

	sig := make([]byte, WotsLen*WotsN)
	for i := 0; i < WotsLen; i++ {
		element := wotsChain(sk[i], 0, digits[i], pubSeed, i)
		copy(sig[i*WotsN:], element)
	}
	return sig
}

// WOTSPubKeyHex returns the public key as a hex string.
func WOTSPubKeyHex(kp WOTSKeyPair) string {
	return hex.EncodeToString(kp.PK)
}

// WOTSPubKeyHashHex returns the Hash160 of the WOTS+ public key as a hex string.
func WOTSPubKeyHashHex(kp WOTSKeyPair) string {
	return hex.EncodeToString(crypto.Hash160(kp.PK))
}
