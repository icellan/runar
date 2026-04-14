// Package runar provides types and crypto functions for Rúnar smart contract
// development in Go. Contracts import this package to get IDE support,
// type checking, and the ability to run native Go tests.
//
// Crypto functions (CheckSig, VerifyRabinSig, VerifyWOTS, etc.) perform real
// verification using the go-sdk ECDSA library and modular arithmetic.
// CheckPreimage remains mocked (always returns true) since it requires a full
// transaction context. Hash functions (Hash160, Hash256, etc.) compute real hashes.
//
// Test key pairs (Alice, Bob, Charlie) and SignTestMessage() provide deterministic
// ECDSA keys and signatures for contract testing.
//
// Byte types use string as the underlying type so == comparison works
// naturally in contract code, matching Rúnar's === semantics.
package runar

import (
	"crypto/sha256"
	"encoding/binary"
	"math"

	"golang.org/x/crypto/ripemd160"
)

// ---------------------------------------------------------------------------
// Scalar types — aliases so Go arithmetic operators work directly
// ---------------------------------------------------------------------------

// Int is a Rúnar integer (maps to Bitcoin Script numbers).
type Int = int64

// Bigint is an alias for Int.
type Bigint = int64

// Bool is a Rúnar boolean.
type Bool = bool

// ---------------------------------------------------------------------------
// Byte-string types — backed by string so == works for equality checks
// ---------------------------------------------------------------------------

// ByteString is an arbitrary byte sequence.
type ByteString string

// PubKey is a public key (compressed or uncompressed).
type PubKey = ByteString

// Sig is a DER-encoded signature.
type Sig = ByteString

// Addr is a 20-byte address (typically a hash160 of a public key).
type Addr = ByteString

// Sha256 is a 32-byte SHA-256 hash.
type Sha256 = ByteString

// Ripemd160Hash is a 20-byte RIPEMD-160 hash.
type Ripemd160Hash = ByteString

// SigHashPreimage is the sighash preimage for transaction validation.
type SigHashPreimage = ByteString

// RabinSig is a Rabin signature.
type RabinSig = ByteString

// RabinPubKey is a Rabin public key.
type RabinPubKey = ByteString

// Point is a 64-byte EC point (x[32] || y[32], big-endian, no prefix).
type Point = ByteString

// ---------------------------------------------------------------------------
// Base contract structs
// ---------------------------------------------------------------------------

// SmartContract is the base struct for stateless Rúnar contracts.
// Embed this in your contract struct.
type SmartContract struct{}

// OutputSnapshot records a single output from AddOutput.
type OutputSnapshot struct {
	Satoshis int64
	Values   []any
}

// StatefulSmartContract is the base struct for stateful Rúnar contracts.
// Embed this in your contract struct. Provides AddOutput and state tracking.
type StatefulSmartContract struct {
	outputs    []OutputSnapshot
	TxPreimage SigHashPreimage
}

// AddOutput records a new output with the given satoshis and state values.
// The values should match the mutable properties in declaration order.
func (s *StatefulSmartContract) AddOutput(satoshis int64, values ...any) {
	s.outputs = append(s.outputs, OutputSnapshot{
		Satoshis: satoshis,
		Values:   values,
	})
}

// GetStateScript returns a mock state script (empty bytes in test mode).
func (s *StatefulSmartContract) GetStateScript() ByteString {
	return ""
}

// Outputs returns the outputs recorded during the last method execution.
func (s *StatefulSmartContract) Outputs() []OutputSnapshot {
	return s.outputs
}

// ResetOutputs clears recorded outputs (call between test method invocations).
func (s *StatefulSmartContract) ResetOutputs() {
	s.outputs = nil
}

// ---------------------------------------------------------------------------
// Control flow
// ---------------------------------------------------------------------------

// Assert panics if the condition is false, mirroring Bitcoin Script OP_VERIFY.
func Assert(cond bool) {
	if !cond {
		panic("runar: assertion failed")
	}
}

// ---------------------------------------------------------------------------
// Crypto functions — real ECDSA and Rabin verification, mocked preimage
// ---------------------------------------------------------------------------

// CheckSig performs real ECDSA signature verification against TestMessageDigest.
// The signature must be DER-encoded and the public key must be a valid
// compressed or uncompressed secp256k1 key.
func CheckSig(sig Sig, pk PubKey) bool {
	return ecdsaVerify([]byte(sig), []byte(pk), TestMessageDigest[:])
}

// CheckMultiSig performs real ordered multi-signature verification.
// Each signature is verified against the corresponding public key in order,
// matching Bitcoin's OP_CHECKMULTISIG semantics (ordered, 1:1 pairing).
func CheckMultiSig(sigs []Sig, pks []PubKey) bool {
	if len(sigs) > len(pks) {
		return false
	}
	pkIdx := 0
	for _, sig := range sigs {
		matched := false
		for pkIdx < len(pks) {
			if ecdsaVerify([]byte(sig), []byte(pks[pkIdx]), TestMessageDigest[:]) {
				pkIdx++
				matched = true
				break
			}
			pkIdx++
		}
		if !matched {
			return false
		}
	}
	return true
}

// CheckPreimage always returns true in test mode.
// Real preimage verification requires a full transaction context.
func CheckPreimage(preimage SigHashPreimage) bool {
	return true
}

// VerifyRabinSig performs real Rabin signature verification using modular arithmetic.
// Checks that (sig^2 + padding) mod pubkey == SHA256(msg).
func VerifyRabinSig(msg ByteString, sig RabinSig, padding ByteString, pk RabinPubKey) bool {
	return rabinVerifyImpl([]byte(msg), []byte(sig), []byte(padding), []byte(pk))
}

// VerifyWOTS performs real WOTS+ signature verification using SHA-256 hash chains.
func VerifyWOTS(msg ByteString, sig ByteString, pubkey ByteString) bool {
	return wotsVerifyImpl([]byte(msg), []byte(sig), []byte(pubkey))
}

// SLH-DSA (SPHINCS+) SHA-256 variants — real FIPS 205 verification.

func VerifySLHDSA_SHA2_128s(msg ByteString, sig ByteString, pubkey ByteString) bool {
	return SLHVerify(SLH_SHA2_128s, []byte(msg), []byte(sig), []byte(pubkey))
}
func VerifySLHDSA_SHA2_128f(msg ByteString, sig ByteString, pubkey ByteString) bool {
	return SLHVerify(SLH_SHA2_128f, []byte(msg), []byte(sig), []byte(pubkey))
}
func VerifySLHDSA_SHA2_192s(msg ByteString, sig ByteString, pubkey ByteString) bool {
	return SLHVerify(SLH_SHA2_192s, []byte(msg), []byte(sig), []byte(pubkey))
}
func VerifySLHDSA_SHA2_192f(msg ByteString, sig ByteString, pubkey ByteString) bool {
	return SLHVerify(SLH_SHA2_192f, []byte(msg), []byte(sig), []byte(pubkey))
}
func VerifySLHDSA_SHA2_256s(msg ByteString, sig ByteString, pubkey ByteString) bool {
	return SLHVerify(SLH_SHA2_256s, []byte(msg), []byte(sig), []byte(pubkey))
}
func VerifySLHDSA_SHA2_256f(msg ByteString, sig ByteString, pubkey ByteString) bool {
	return SLHVerify(SLH_SHA2_256f, []byte(msg), []byte(sig), []byte(pubkey))
}

// ---------------------------------------------------------------------------
// EC (elliptic curve) functions — real secp256k1 arithmetic for testing.
// In compiled Bitcoin Script, these map to EC codegen opcodes.
// ---------------------------------------------------------------------------

// EC functions are in ec.go

// ---------------------------------------------------------------------------
// Real hash functions
// ---------------------------------------------------------------------------

// Hash160 computes RIPEMD160(SHA256(data)), producing a 20-byte address.
func Hash160(data PubKey) Addr {
	h := sha256.Sum256([]byte(data))
	r := ripemd160.New()
	r.Write(h[:])
	return Addr(r.Sum(nil))
}

// Hash256 computes SHA256(SHA256(data)), producing a 32-byte hash.
func Hash256(data ByteString) Sha256 {
	h1 := sha256.Sum256([]byte(data))
	h2 := sha256.Sum256(h1[:])
	return Sha256(h2[:])
}

// Sha256Hash computes a single SHA-256 hash.
func Sha256Hash(data ByteString) Sha256 {
	h := sha256.Sum256([]byte(data))
	return Sha256(h[:])
}

// Ripemd160Func computes a RIPEMD-160 hash.
func Ripemd160Func(data ByteString) Ripemd160Hash {
	r := ripemd160.New()
	r.Write([]byte(data))
	return Ripemd160Hash(r.Sum(nil))
}

// ---------------------------------------------------------------------------
// Mock BLAKE3 functions (compiler intrinsics — stubs return 32 zero bytes)
// ---------------------------------------------------------------------------

// Blake3Compress is a mock BLAKE3 single-block compression.
// In compiled Bitcoin Script this expands to ~10,000 opcodes.
// The mock returns 32 zero bytes for business-logic testing.
func Blake3Compress(chainingValue, block ByteString) ByteString {
	return ByteString(make([]byte, 32))
}

// Blake3Hash is a mock BLAKE3 hash for messages up to 64 bytes.
// In compiled Bitcoin Script this uses the IV as the chaining value and
// applies zero-padding before calling the compression function.
// The mock returns 32 zero bytes for business-logic testing.
func Blake3Hash(message ByteString) ByteString {
	return ByteString(make([]byte, 32))
}

// ---------------------------------------------------------------------------
// SHA-256 compression / finalization (FIPS 180-4 Section 6.2.2)
// ---------------------------------------------------------------------------

// sha256K contains the 64 round constants for SHA-256.
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

// Sha256Compress performs a single SHA-256 compression function (FIPS 180-4 Section 6.2.2).
// state must be 32 bytes (8 big-endian uint32 words H[0..7]).
// block must be 64 bytes (the 512-bit message block).
// Returns the updated 32-byte state.
func Sha256Compress(state, block ByteString) ByteString {
	if len(state) != 32 {
		panic("Sha256Compress: state must be 32 bytes")
	}
	if len(block) != 64 {
		panic("Sha256Compress: block must be 64 bytes")
	}

	// Parse state into 8 uint32 words
	var h [8]uint32
	for i := 0; i < 8; i++ {
		h[i] = binary.BigEndian.Uint32([]byte(state)[i*4 : i*4+4])
	}

	// Parse block into 16 uint32 words and expand to 64
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32([]byte(block)[i*4 : i*4+4])
	}
	for t := 16; t < 64; t++ {
		// sigma0(x) = ROTR(7,x) ^ ROTR(18,x) ^ SHR(3,x)
		x := w[t-15]
		s0 := (x>>7 | x<<25) ^ (x>>18 | x<<14) ^ (x >> 3)
		// sigma1(x) = ROTR(17,x) ^ ROTR(19,x) ^ SHR(10,x)
		x = w[t-2]
		s1 := (x>>17 | x<<15) ^ (x>>19 | x<<13) ^ (x >> 10)
		w[t] = s1 + w[t-7] + s0 + w[t-16]
	}

	// Initialize working variables
	a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]

	// 64 compression rounds
	for t := 0; t < 64; t++ {
		// Sigma1(e) = ROTR(6,e) ^ ROTR(11,e) ^ ROTR(25,e)
		S1 := (e>>6 | e<<26) ^ (e>>11 | e<<21) ^ (e>>25 | e<<7)
		// Ch(e,f,g) = (e AND f) XOR (NOT e AND g)
		ch := (e & f) ^ (^e & g)
		temp1 := hh + S1 + ch + sha256K[t] + w[t]
		// Sigma0(a) = ROTR(2,a) ^ ROTR(13,a) ^ ROTR(22,a)
		S0 := (a>>2 | a<<30) ^ (a>>13 | a<<19) ^ (a>>22 | a<<10)
		// Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := S0 + maj

		hh = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	}

	// Add working variables to current hash value
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
	h[4] += e
	h[5] += f
	h[6] += g
	h[7] += hh

	// Encode result as 32 big-endian bytes
	out := make([]byte, 32)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:i*4+4], h[i])
	}
	return ByteString(out)
}

// Sha256Finalize applies FIPS 180-4 padding to the remaining bytes and performs
// the final compression round(s).
// state must be 32 bytes (the intermediate hash state).
// remaining is the unprocessed trailing bytes.
// msgBitLen is the total message length in bits.
// Returns the final 32-byte SHA-256 digest.
func Sha256Finalize(state, remaining ByteString, msgBitLen int64) ByteString {
	if len(state) != 32 {
		panic("Sha256Finalize: state must be 32 bytes")
	}

	// Start padding: append 0x80
	padded := append([]byte(nil), []byte(remaining)...)
	padded = append(padded, 0x80)

	if len(padded)+8 <= 64 {
		// Fits in one block: zero-pad to 56 bytes, then append 8-byte BE bit length
		for len(padded) < 56 {
			padded = append(padded, 0)
		}
		var bitLen [8]byte
		binary.BigEndian.PutUint64(bitLen[:], uint64(msgBitLen))
		padded = append(padded, bitLen[:]...)
		return Sha256Compress(state, ByteString(padded))
	}

	// Needs two blocks: zero-pad to 120 bytes, then append 8-byte BE bit length
	for len(padded) < 120 {
		padded = append(padded, 0)
	}
	var bitLen [8]byte
	binary.BigEndian.PutUint64(bitLen[:], uint64(msgBitLen))
	padded = append(padded, bitLen[:]...)

	// Compress first block
	intermediate := Sha256Compress(state, ByteString(padded[:64]))
	// Compress second block
	return Sha256Compress(intermediate, ByteString(padded[64:128]))
}

// ---------------------------------------------------------------------------
// Mock preimage extraction functions
// ---------------------------------------------------------------------------

// ExtractLocktime returns 0 in test mode.
func ExtractLocktime(p SigHashPreimage) int64 { return 0 }

// ExtractOutputHash returns the first 32 bytes of the preimage in test mode.
// Tests set TxPreimage = Hash256(expectedOutputBytes) so the assertion
// Hash256(outputs) == ExtractOutputHash(TxPreimage) passes.
// Falls back to 32 zero bytes when the preimage is unset (nil/empty).
func ExtractOutputHash(p SigHashPreimage) Sha256 {
	if len(p) >= 32 {
		result := make([]byte, 32)
		copy(result, p[:32])
		return Sha256(result)
	}
	return Sha256(make([]byte, 32))
}

// ExtractAmount returns 10000 in test mode.
func ExtractAmount(p SigHashPreimage) int64 { return 10000 }

// ExtractVersion returns 1 in test mode.
func ExtractVersion(p SigHashPreimage) int64 { return 1 }

// ExtractSequence returns 0xffffffff in test mode.
func ExtractSequence(p SigHashPreimage) int64 { return 0xffffffff }

// ExtractHashPrevouts returns Hash256(72 zero bytes) in test mode.
// This is consistent with passing allPrevouts = 72 zero bytes in tests,
// since ExtractOutpoint also returns 36 zero bytes.
func ExtractHashPrevouts(p SigHashPreimage) Sha256 { return Hash256(ByteString(make([]byte, 72))) }

// ExtractOutpoint returns 36 zero bytes in test mode.
func ExtractOutpoint(p SigHashPreimage) ByteString { return ByteString(make([]byte, 36)) }

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// Num2Bin converts an integer to a byte string of the specified length
// using Bitcoin Script's little-endian signed magnitude encoding.
// Panics if v == math.MinInt64 (|MinInt64| overflows int64).
func Num2Bin(v int64, length int64) ByteString {
	if v == math.MinInt64 {
		panic("runar: int64 overflow in Num2Bin — |MinInt64| not representable; Bitcoin Script supports arbitrary precision but Go uses int64; see compilers/go/README.md")
	}
	buf := make([]byte, length)
	if v == 0 {
		return ByteString(buf)
	}
	abs := v
	if abs < 0 {
		abs = -abs
	}
	uval := uint64(abs)
	for i := int64(0); i < length && uval > 0; i++ {
		buf[i] = byte(uval & 0xff)
		uval >>= 8
	}
	if v < 0 {
		buf[length-1] |= 0x80
	}
	return ByteString(buf[:length])
}

// Bin2Num converts a byte string (Bitcoin Script LE signed-magnitude) back to
// an integer. Inverse of Num2Bin.
func Bin2Num(data ByteString) int64 {
	if len(data) == 0 {
		return 0
	}
	last := data[len(data)-1]
	negative := (last & 0x80) != 0
	var result uint64
	result = uint64(last & 0x7f)
	for i := len(data) - 2; i >= 0; i-- {
		result = (result << 8) | uint64(data[i])
	}
	if negative {
		return -int64(result)
	}
	return int64(result)
}

// Len returns the length of a byte string as an integer.
func Len(data ByteString) int64 {
	return int64(len(data))
}

// Cat concatenates two byte strings.
func Cat(a, b ByteString) ByteString {
	return a + b
}

// Substr returns a substring of a byte string.
func Substr(data ByteString, start, length int64) ByteString {
	return data[start : start+length]
}

// ReverseBytes returns a reversed copy of a byte string.
func ReverseBytes(data ByteString) ByteString {
	b := []byte(data)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return ByteString(b)
}

// Abs returns the absolute value. Panics if n == math.MinInt64 (not representable as positive int64).
func Abs(n int64) int64 {
	if n == math.MinInt64 {
		panic("runar: int64 overflow in Abs(MinInt64) — Bitcoin Script supports arbitrary precision but Go uses int64; see compilers/go/README.md")
	}
	if n < 0 {
		return -n
	}
	return n
}

// Min returns the smaller of two values.
func Min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// Max returns the larger of two values.
func Max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// Within returns true if min <= value < max.
func Within(value, min, max int64) bool {
	return value >= min && value < max
}

// Safediv divides a by b, panicking if b is zero.
func Safediv(a, b int64) int64 {
	if b == 0 {
		panic("safediv: division by zero")
	}
	return a / b
}

// Safemod computes a % b, panicking if b is zero.
func Safemod(a, b int64) int64 {
	if b == 0 {
		panic("safemod: modulo by zero")
	}
	return a % b
}

// Clamp constrains value to the range [lo, hi].
func Clamp(value, lo, hi int64) int64 {
	if value < lo {
		return lo
	}
	if value > hi {
		return hi
	}
	return value
}

// Sign returns -1, 0, or 1 depending on the sign of n.
func Sign(n int64) int64 {
	if n > 0 {
		return 1
	}
	if n < 0 {
		return -1
	}
	return 0
}

// Pow computes base^exp for non-negative exponents. Panics on int64 overflow.
func Pow(base, exp int64) int64 {
	if exp < 0 {
		panic("pow: negative exponent")
	}
	result := int64(1)
	for i := int64(0); i < exp; i++ {
		result = checkedMul(result, base)
	}
	return result
}

// MulDiv computes (a * b) / c. Panics on int64 overflow in a*b.
func MulDiv(a, b, c int64) int64 {
	if c == 0 {
		panic("mulDiv: division by zero")
	}
	return checkedMul(a, b) / c
}

// PercentOf computes (amount * bps) / 10000 (basis points). Panics on int64 overflow.
func PercentOf(amount, bps int64) int64 {
	return checkedMul(amount, bps) / 10000
}

// Sqrt computes the integer square root via Newton's method. Panics on int64 overflow.
func Sqrt(n int64) int64 {
	if n < 0 {
		panic("sqrt: negative input")
	}
	if n == 0 {
		return 0
	}
	guess := n
	for i := 0; i < 256; i++ {
		next := checkedAdd(guess, n/guess) / 2
		if next >= guess {
			break
		}
		guess = next
	}
	return guess
}

// Gcd computes the greatest common divisor via Euclidean algorithm.
// Panics if either argument is math.MinInt64 (|MinInt64| overflows int64).
func Gcd(a, b int64) int64 {
	if a == math.MinInt64 || b == math.MinInt64 {
		panic("runar: int64 overflow in Gcd — |MinInt64| not representable; Bitcoin Script supports arbitrary precision but Go uses int64; see compilers/go/README.md")
	}
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Divmod returns the quotient of a / b.
func Divmod(a, b int64) int64 {
	if b == 0 {
		panic("divmod: division by zero")
	}
	return a / b
}

// Log2 returns the approximate floor(log2(n)).
func Log2(n int64) int64 {
	if n <= 0 {
		return 0
	}
	bits := int64(0)
	val := n
	for val > 1 {
		val >>= 1
		bits++
	}
	return bits
}

// ToBool returns true if n is non-zero.
func ToBool(n int64) bool {
	return n != 0
}

// ---------------------------------------------------------------------------
// Baby Bear field arithmetic (p = 2^31 - 2^27 + 1 = 2013265921)
// ---------------------------------------------------------------------------

const bbP int64 = 2013265921

// BbFieldAdd returns (a + b) mod p.
func BbFieldAdd(a, b int64) int64 {
	return (a + b) % bbP
}

// BbFieldSub returns (a - b + p) mod p.
func BbFieldSub(a, b int64) int64 {
	return ((a - b) % bbP + bbP) % bbP
}

// BbFieldMul returns (a * b) mod p.
func BbFieldMul(a, b int64) int64 {
	return (a * b) % bbP
}

// BbFieldInv returns the multiplicative inverse of a mod p via Fermat's little theorem.
func BbFieldInv(a int64) int64 {
	result := int64(1)
	base := ((a % bbP) + bbP) % bbP
	exp := bbP - 2
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * base) % bbP
		}
		base = (base * base) % bbP
		exp >>= 1
	}
	return result
}

// ---------------------------------------------------------------------------
// Baby Bear quartic extension field (Fp4 over Fp, W = 11)
// ---------------------------------------------------------------------------
//
// Fp4 = Fp[X] / (X^4 - 11). An element (a0, a1, a2, a3) represents
// a0 + a1*X + a2*X^2 + a3*X^3. Multiplication uses X^4 = W = 11.
//
// Product formula for (a0,a1,a2,a3) * (b0,b1,b2,b3):
//   r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
//   r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
//   r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
//   r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0

const bbW int64 = 11

// BbExt4Mul0 returns component 0 of the quartic extension field product.
func BbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3 int64) int64 {
	r := BbFieldMul(a0, b0)
	t := BbFieldAdd(BbFieldMul(a1, b3), BbFieldAdd(BbFieldMul(a2, b2), BbFieldMul(a3, b1)))
	r = BbFieldAdd(r, BbFieldMul(bbW, t))
	return r
}

// BbExt4Mul1 returns component 1 of the quartic extension field product.
func BbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3 int64) int64 {
	r := BbFieldAdd(BbFieldMul(a0, b1), BbFieldMul(a1, b0))
	t := BbFieldAdd(BbFieldMul(a2, b3), BbFieldMul(a3, b2))
	r = BbFieldAdd(r, BbFieldMul(bbW, t))
	return r
}

// BbExt4Mul2 returns component 2 of the quartic extension field product.
func BbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3 int64) int64 {
	r := BbFieldAdd(BbFieldMul(a0, b2), BbFieldAdd(BbFieldMul(a1, b1), BbFieldMul(a2, b0)))
	r = BbFieldAdd(r, BbFieldMul(bbW, BbFieldMul(a3, b3)))
	return r
}

// BbExt4Mul3 returns component 3 of the quartic extension field product.
func BbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3 int64) int64 {
	return BbFieldAdd(BbFieldMul(a0, b3),
		BbFieldAdd(BbFieldMul(a1, b2),
			BbFieldAdd(BbFieldMul(a2, b1), BbFieldMul(a3, b0))))
}

// ---------------------------------------------------------------------------
// KoalaBear field arithmetic (p = 2^31 - 2^24 + 1 = 2,130,706,433)
// ---------------------------------------------------------------------------

const kbP int64 = 2130706433

// KbFieldAdd returns (a + b) mod p.
func KbFieldAdd(a, b int64) int64 {
	return (a + b) % kbP
}

// KbFieldSub returns (a - b + p) mod p.
func KbFieldSub(a, b int64) int64 {
	return ((a - b) % kbP + kbP) % kbP
}

// KbFieldMul returns (a * b) mod p.
func KbFieldMul(a, b int64) int64 {
	return (a * b) % kbP
}

// KbFieldInv returns the multiplicative inverse of a mod p via Fermat's little theorem.
func KbFieldInv(a int64) int64 {
	result := int64(1)
	base := ((a % kbP) + kbP) % kbP
	exp := kbP - 2
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * base) % kbP
		}
		base = (base * base) % kbP
		exp >>= 1
	}
	return result
}

// ---------------------------------------------------------------------------
// KoalaBear quartic extension field (x^4 - 3, W = 3)
// ---------------------------------------------------------------------------

const kbW int64 = 3

// KbExt4Mul0 returns component 0 of the quartic extension field product over KoalaBear.
func KbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3 int64) int64 {
	r := KbFieldMul(a0, b0)
	t := KbFieldAdd(KbFieldMul(a1, b3), KbFieldAdd(KbFieldMul(a2, b2), KbFieldMul(a3, b1)))
	r = KbFieldAdd(r, KbFieldMul(kbW, t))
	return r
}

// KbExt4Mul1 returns component 1 of the quartic extension field product over KoalaBear.
func KbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3 int64) int64 {
	r := KbFieldAdd(KbFieldMul(a0, b1), KbFieldMul(a1, b0))
	t := KbFieldAdd(KbFieldMul(a2, b3), KbFieldMul(a3, b2))
	r = KbFieldAdd(r, KbFieldMul(kbW, t))
	return r
}

// KbExt4Mul2 returns component 2 of the quartic extension field product over KoalaBear.
func KbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3 int64) int64 {
	r := KbFieldAdd(KbFieldMul(a0, b2), KbFieldAdd(KbFieldMul(a1, b1), KbFieldMul(a2, b0)))
	r = KbFieldAdd(r, KbFieldMul(kbW, KbFieldMul(a3, b3)))
	return r
}

// KbExt4Mul3 returns component 3 of the quartic extension field product over KoalaBear.
func KbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3 int64) int64 {
	return KbFieldAdd(KbFieldMul(a0, b3),
		KbFieldAdd(KbFieldMul(a1, b2),
			KbFieldAdd(KbFieldMul(a2, b1), KbFieldMul(a3, b0))))
}

// KbExt4Inv0 returns component 0 of the quartic extension field inverse over KoalaBear.
func KbExt4Inv0(a0, a1, a2, a3 int64) int64 {
	r := kbExt4Inv(a0, a1, a2, a3)
	return r[0]
}

// KbExt4Inv1 returns component 1 of the quartic extension field inverse over KoalaBear.
func KbExt4Inv1(a0, a1, a2, a3 int64) int64 {
	r := kbExt4Inv(a0, a1, a2, a3)
	return r[1]
}

// KbExt4Inv2 returns component 2 of the quartic extension field inverse over KoalaBear.
func KbExt4Inv2(a0, a1, a2, a3 int64) int64 {
	r := kbExt4Inv(a0, a1, a2, a3)
	return r[2]
}

// KbExt4Inv3 returns component 3 of the quartic extension field inverse over KoalaBear.
func KbExt4Inv3(a0, a1, a2, a3 int64) int64 {
	r := kbExt4Inv(a0, a1, a2, a3)
	return r[3]
}

// kbExt4Inv computes the inverse of a quartic extension field element.
// Uses the formula: inv(a) = conj(a) / norm(a), where norm(a) is in Fp2,
// then inv(norm) is computed and multiplied back.
func kbExt4Inv(a0, a1, a2, a3 int64) [4]int64 {
	// norm = a * conj(a) where conj swaps sign of odd components
	// For x^4 - W: conj(a0,a1,a2,a3) = (a0,-a1,a2,-a3)
	// norm_0 = a0^2 + W*a2^2 - W*(2*a1*a3)  -- but this is actually the Fp2 norm
	// Simpler: compute via brute-force: find b such that a*b = 1
	// Using the standard quartic inverse formula:
	// Let t0 = a0^2, t1 = a1^2, t2 = a2^2, t3 = a3^2
	// s0 = t0 - W*(a1*a3*2 - t2*W) -- this gets complex

	// Simpler approach: compute a * conj(a) to get Fp2 element, then invert
	// conj(a) for x^4-W: (a0, -a1, a2, -a3)
	c0, c1, c2, c3 := a0, KbFieldSub(0, a1), a2, KbFieldSub(0, a3)

	// product = a * conj(a) — should land in Fp2 (components 1,3 = 0)
	p0 := KbExt4Mul0(a0, a1, a2, a3, c0, c1, c2, c3)
	p2 := KbExt4Mul2(a0, a1, a2, a3, c0, c1, c2, c3)
	// p1 and p3 should be 0, forming Fp2 element (p0, p2)

	// Now invert the Fp2 element (p0, p2) where the Fp2 is x^2 - W
	// inv(p0 + p2*x^2) = (p0 - p2*x^2) / (p0^2 - W*p2^2)
	normSq := KbFieldSub(KbFieldMul(p0, p0), KbFieldMul(kbW, KbFieldMul(p2, p2)))
	normInv := KbFieldInv(normSq)

	inv0 := KbFieldMul(p0, normInv)
	inv2 := KbFieldSub(0, KbFieldMul(p2, normInv))

	// result = conj(a) * inv(norm) = (c0,c1,c2,c3) * (inv0, 0, inv2, 0)
	r0 := KbFieldAdd(KbFieldMul(c0, inv0), KbFieldMul(kbW, KbFieldMul(c2, inv2)))
	r1 := KbFieldAdd(KbFieldMul(c1, inv0), KbFieldMul(kbW, KbFieldMul(c3, inv2)))
	r2 := KbFieldAdd(KbFieldMul(c0, inv2), KbFieldMul(c2, inv0))
	r3 := KbFieldAdd(KbFieldMul(c1, inv2), KbFieldMul(c3, inv0))

	return [4]int64{r0, r1, r2, r3}
}

// ---------------------------------------------------------------------------
// Poseidon2 KoalaBear compression (mock for testing)
// ---------------------------------------------------------------------------

// poseidon2KBWidth is the state width.
const poseidon2KBWidth = 16

// poseidon2KBSbox computes x^3 mod p.
func poseidon2KBSbox(x int64) int64 {
	x2 := KbFieldMul(x, x)
	return KbFieldMul(x, x2)
}

// poseidon2KBExternalMDS4 applies circ(2,3,1,1) to a 4-element block.
func poseidon2KBExternalMDS4(a, b, c, d int64) (int64, int64, int64, int64) {
	sum := KbFieldAdd(KbFieldAdd(a, b), KbFieldAdd(c, d))
	out0 := KbFieldAdd(sum, KbFieldAdd(a, KbFieldMul(b, 2)))
	out1 := KbFieldAdd(sum, KbFieldAdd(b, KbFieldMul(c, 2)))
	out2 := KbFieldAdd(sum, KbFieldAdd(c, KbFieldMul(d, 2)))
	out3 := KbFieldAdd(sum, KbFieldAdd(d, KbFieldMul(a, 2)))
	return out0, out1, out2, out3
}

// poseidon2KBRoundConstants holds the round constants for all 28 rounds.
// Each round has 16 constants. For external rounds, all 16 are used.
// For internal rounds (4-23), only element [0] is used (rest are zero).
//
// From Plonky3 p3-koala-bear 0.5.2:
//   KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, _INTERNAL, _EXTERNAL_FINAL
var poseidon2KBRoundConstants = [28][poseidon2KBWidth]int64{
	// External initial rounds (0-3)
	{2128964168, 288780357, 316938561, 2126233899, 426817493, 1714118888, 1045008582, 1738510837, 889721787, 8866516, 681576474, 419059826, 1596305521, 1583176088, 1584387047, 1529751136},
	{1863858111, 1072044075, 517831365, 1464274176, 1138001621, 428001039, 245709561, 1641420379, 1365482496, 770454828, 693167409, 757905735, 136670447, 436275702, 525466355, 1559174242},
	{1030087950, 869864998, 322787870, 267688717, 948964561, 740478015, 679816114, 113662466, 2066544572, 1744924186, 367094720, 1380455578, 1842483872, 416711434, 1342291586, 1692058446},
	{1493348999, 1113949088, 210900530, 1071655077, 610242121, 1136339326, 2020858841, 1019840479, 678147278, 1678413261, 1361743414, 61132629, 1209546658, 64412292, 1936878279, 1980661727},

	// Internal rounds (4-23) — only element [0] is used
	{1423960925, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{2101391318, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1915532054, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{275400051, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1168624859, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1141248885, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{356546469, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1165250474, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1320543726, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{932505663, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1204226364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1452576828, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1774936729, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{926808140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1184948056, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1186493834, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{843181003, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{185193011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{452207447, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{510054082, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

	// External final rounds (24-27)
	{1139268644, 630873441, 669538875, 462500858, 876500520, 1214043330, 383937013, 375087302, 636912601, 307200505, 390279673, 1999916485, 1518476730, 1606686591, 1410677749, 1581191572},
	{1004269969, 143426723, 1747283099, 1016118214, 1749423722, 66331533, 1177761275, 1581069649, 1851371119, 852520128, 1499632627, 1820847538, 150757557, 884787840, 619710451, 1651711087},
	{505263814, 212076987, 1482432120, 1458130652, 382871348, 417404007, 2066495280, 1996518884, 902934924, 582892981, 1337064375, 1199354861, 2102596038, 1533193853, 1436311464, 2012303432},
	{839997195, 1225781098, 2011967775, 575084315, 1309329169, 786393545, 995788880, 1702925345, 1444525226, 908073383, 1811535085, 1531002367, 1635653662, 1585100155, 867006515, 879151050},
}

// poseidon2KBPermute applies the Poseidon2 permutation to a 16-element state.
// Uses real round constants from Plonky3 p3-koala-bear (SP1 v6.0.2).
func poseidon2KBPermute(state *[poseidon2KBWidth]int64) {
	externalMDS := func() {
		// Step 1: Apply circ(2,3,1,1) to each group of 4
		for g := 0; g < 4; g++ {
			state[g*4], state[g*4+1], state[g*4+2], state[g*4+3] =
				poseidon2KBExternalMDS4(state[g*4], state[g*4+1], state[g*4+2], state[g*4+3])
		}
		// Step 2: Cross-group mixing — add sum of position-equivalent elements
		var sums [4]int64
		for k := 0; k < 4; k++ {
			for j := 0; j < poseidon2KBWidth; j += 4 {
				sums[k] = KbFieldAdd(sums[k], state[j+k])
			}
		}
		for i := 0; i < poseidon2KBWidth; i++ {
			state[i] = KbFieldAdd(state[i], sums[i%4])
		}
	}

	// kbHalve computes x/2 in the field.
	kbHalve := func(x int64) int64 {
		if x%2 == 0 {
			return x / 2
		}
		return (x + kbP) / 2
	}
	// kbDiv2Exp computes x / 2^n in the field.
	kbDiv2Exp := func(x int64, n uint) int64 {
		for i := uint(0); i < n; i++ {
			x = kbHalve(x)
		}
		return x
	}

	internalDiffusion := func() {
		// Exact port of Plonky3 internal_layer_mat_mul for KoalaBear width-16.
		// V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
		partSum := int64(0)
		for i := 1; i < poseidon2KBWidth; i++ {
			partSum = KbFieldAdd(partSum, state[i])
		}
		fullSum := KbFieldAdd(partSum, state[0])
		state[0] = KbFieldSub(partSum, state[0])

		state[1] = KbFieldAdd(state[1], fullSum)
		state[2] = KbFieldAdd(KbFieldMul(state[2], 2), fullSum)
		state[3] = KbFieldAdd(kbHalve(state[3]), fullSum)
		state[4] = KbFieldAdd(fullSum, KbFieldAdd(KbFieldMul(state[4], 2), state[4]))
		state[5] = KbFieldAdd(fullSum, KbFieldMul(KbFieldMul(state[5], 2), 2))
		state[6] = KbFieldSub(fullSum, kbHalve(state[6]))
		state[7] = KbFieldSub(fullSum, KbFieldAdd(KbFieldMul(state[7], 2), state[7]))
		state[8] = KbFieldSub(fullSum, KbFieldMul(KbFieldMul(state[8], 2), 2))
		state[9] = KbFieldAdd(kbDiv2Exp(state[9], 8), fullSum)
		state[10] = KbFieldAdd(kbDiv2Exp(state[10], 3), fullSum)
		state[11] = KbFieldAdd(kbDiv2Exp(state[11], 24), fullSum)
		state[12] = KbFieldSub(fullSum, kbDiv2Exp(state[12], 8))
		state[13] = KbFieldSub(fullSum, kbDiv2Exp(state[13], 3))
		state[14] = KbFieldSub(fullSum, kbDiv2Exp(state[14], 4))
		state[15] = KbFieldSub(fullSum, kbDiv2Exp(state[15], 24))
	}

	// Initial MDS before external rounds (Plonky3's external_initial_permute_state)
	externalMDS()

	// Phase 1: 4 external rounds (rounds 0-3)
	for r := 0; r < 4; r++ {
		for i := 0; i < poseidon2KBWidth; i++ {
			state[i] = KbFieldAdd(state[i], poseidon2KBRoundConstants[r][i])
		}
		for i := 0; i < poseidon2KBWidth; i++ {
			state[i] = poseidon2KBSbox(state[i])
		}
		externalMDS()
	}

	// Phase 2: 20 internal rounds (rounds 4-23)
	for r := 0; r < 20; r++ {
		state[0] = KbFieldAdd(state[0], poseidon2KBRoundConstants[4+r][0])
		state[0] = poseidon2KBSbox(state[0])
		internalDiffusion()
	}

	// Phase 3: 4 external rounds (rounds 24-27)
	for r := 0; r < 4; r++ {
		for i := 0; i < poseidon2KBWidth; i++ {
			state[i] = KbFieldAdd(state[i], poseidon2KBRoundConstants[24+r][i])
		}
		for i := 0; i < poseidon2KBWidth; i++ {
			state[i] = poseidon2KBSbox(state[i])
		}
		externalMDS()
	}
}

// poseidon2KBCompress compresses two 8-element digests into one 8-element digest.
func poseidon2KBCompress(left, right [8]int64) [8]int64 {
	var state [poseidon2KBWidth]int64
	copy(state[0:8], left[:])
	copy(state[8:16], right[:])
	poseidon2KBPermute(&state)
	var digest [8]int64
	copy(digest[:], state[0:8])
	return digest
}

// MerkleRootPoseidon2KBv is a variadic wrapper for contract compatibility.
// Takes individual int64 arguments: leaf[0..7], proof[0..depth*8-1], index, depth.
// Returns the first element of the 8-element Poseidon2 digest (matching the
// contract type system's single bigint return).
func MerkleRootPoseidon2KBv(args ...int64) int64 {
	if len(args) < 10 {
		panic("MerkleRootPoseidon2KBv: need at least 10 args (8 leaf + index + depth)")
	}
	depth := args[len(args)-1]
	index := args[len(args)-2]
	var leaf [8]int64
	copy(leaf[:], args[0:8])
	proof := args[8 : len(args)-2]
	result := MerkleRootPoseidon2KB(leaf, proof, index, depth)
	return result[0]
}

// MerkleRootPoseidon2KB computes a Poseidon2 KoalaBear Merkle root.
// leaf is 8 field elements, proof is depth*8 field elements (consecutive siblings),
// index determines left/right at each level, depth is the tree depth.
// Returns the 8-element root digest.
func MerkleRootPoseidon2KB(leaf [8]int64, proof []int64, index, depth int64) [8]int64 {
	current := leaf
	for i := int64(0); i < depth; i++ {
		var sibling [8]int64
		copy(sibling[:], proof[i*8:(i+1)*8])
		bit := (index >> uint(i)) & 1
		if bit == 1 {
			current = poseidon2KBCompress(sibling, current)
		} else {
			current = poseidon2KBCompress(current, sibling)
		}
	}
	return current
}

// ---------------------------------------------------------------------------
// Merkle proof verification
// ---------------------------------------------------------------------------

// MerkleRootSha256 computes a Merkle root using SHA-256 as the hash function.
// leaf is a 32-byte hash, proof is depth*32 concatenated sibling hashes,
// index determines left/right at each level, depth is the tree depth.
func MerkleRootSha256(leaf ByteString, proof ByteString, index, depth int64) ByteString {
	return merkleRootImpl(leaf, proof, index, depth, Sha256Hash)
}

// MerkleRootHash256 computes a Merkle root using Hash256 (double SHA-256).
// Same parameters as MerkleRootSha256 but uses Hash256 instead.
func MerkleRootHash256(leaf ByteString, proof ByteString, index, depth int64) ByteString {
	return merkleRootImpl(leaf, proof, index, depth, Hash256)
}

func merkleRootImpl(leaf ByteString, proof ByteString, index, depth int64, hashFn func(ByteString) ByteString) ByteString {
	current := leaf
	for i := int64(0); i < depth; i++ {
		sibling := proof[i*32 : (i+1)*32]
		bit := (index >> uint(i)) & 1
		var preimage ByteString
		if bit == 1 {
			preimage = sibling + current
		} else {
			preimage = current + sibling
		}
		current = hashFn(preimage)
	}
	return current
}

// ---------------------------------------------------------------------------
// Groth16 verification
// ---------------------------------------------------------------------------

// Groth16Verify verifies a Groth16/BN254 proof against the given public
// values and verifying key hash. The proofBlob is a 256-byte serialized
// Groth16 proof wrapping the SP1 STARK.
//
// Mock: always returns true. The compiled Bitcoin Script performs the
// real BN254 pairing check via the Groth16 verifier codegen.
func Groth16Verify(proofBlob ByteString, publicValues ByteString, vkHash ByteString) bool {
	_ = proofBlob
	_ = publicValues
	_ = vkHash
	return true
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// MockPreimage returns a dummy sighash preimage for testing.
func MockPreimage() SigHashPreimage {
	return SigHashPreimage(make([]byte, 181))
}
