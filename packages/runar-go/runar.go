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
// Test helpers
// ---------------------------------------------------------------------------

// MockPreimage returns a dummy sighash preimage for testing.
func MockPreimage() SigHashPreimage {
	return SigHashPreimage(make([]byte, 181))
}
