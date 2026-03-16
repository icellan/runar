package runar

import (
	"crypto/sha256"
	"math/big"
)

// ---------------------------------------------------------------------------
// Rabin signature verification — real modular arithmetic using math/big
// ---------------------------------------------------------------------------

// Rabin test key primes (same as TypeScript test keys).
// p = 1361129467683753853853498429727072846227
// q = 1361129467683753853853498429727082846007
var (
	rabinP, _ = new(big.Int).SetString("1361129467683753853853498429727072846227", 10)
	rabinQ, _ = new(big.Int).SetString("1361129467683753853853498429727082846007", 10)
)

// RabinTestKeyN is the Rabin modulus n = p * q, stored as raw LE bytes (ByteString).
var RabinTestKeyN RabinPubKey

func init() {
	n := new(big.Int).Mul(rabinP, rabinQ)
	RabinTestKeyN = RabinPubKey(bigIntToLEBytes(n))
}

// rabinVerifyImpl performs real Rabin signature verification.
//
// Verification equation: (sig^2 + padding) mod n === SHA256(msg) mod n
//
// All byte values (sig, padding, pubkey) are interpreted as little-endian
// unsigned big integers, matching Bitcoin Script's number encoding.
// The SHA256 hash is also interpreted as unsigned little-endian.
func rabinVerifyImpl(msg, sig, padding, pubkey []byte) bool {
	// Convert bytes to big.Int (little-endian unsigned)
	sigInt := leBytesToBigInt(sig)
	padInt := leBytesToBigInt(padding)
	pkInt := leBytesToBigInt(pubkey)

	if pkInt.Sign() == 0 {
		return false
	}

	// Compute SHA256(msg) as unsigned little-endian big integer
	h := sha256.Sum256(msg)
	hashBN := leBytesToBigInt(h[:])

	// Compute (sig^2 + padding) mod pubkey
	sigSq := new(big.Int).Mul(sigInt, sigInt)
	sum := new(big.Int).Add(sigSq, padInt)
	lhs := new(big.Int).Mod(sum, pkInt)
	// Ensure non-negative
	if lhs.Sign() < 0 {
		lhs.Add(lhs, pkInt)
	}

	// Compute hash mod pubkey
	rhs := new(big.Int).Mod(hashBN, pkInt)
	if rhs.Sign() < 0 {
		rhs.Add(rhs, pkInt)
	}

	return lhs.Cmp(rhs) == 0
}

// RabinSign produces a Rabin signature for the given message using primes p and q.
// Returns (sig, padding) as big.Int values.
//
// The algorithm:
//  1. Compute h = SHA256(msg) as unsigned LE big integer
//  2. n = p * q
//  3. Try padding = 0, 1, 2, ... until (h - padding) is a quadratic residue mod n
//  4. sig = sqrt(h - padding) mod n (using CRT)
//  5. Verify: (sig^2 + padding) mod n === h mod n
func RabinSign(msg []byte, p, q *big.Int) (sig *big.Int, padding *big.Int) {
	h := sha256.Sum256(msg)
	hashBN := leBytesToBigInt(h[:])
	n := new(big.Int).Mul(p, q)

	hashModN := new(big.Int).Mod(hashBN, n)

	for pad := int64(0); pad < 1000; pad++ {
		padBig := big.NewInt(pad)
		// target = (hashBN - padding) mod n
		target := new(big.Int).Sub(hashModN, padBig)
		if target.Sign() < 0 {
			target.Add(target, n)
		}

		root := sqrtModPQ(target, p, q, n)
		if root != nil {
			// Verify: (root^2 + padding) mod n == hashBN mod n
			check := new(big.Int).Mul(root, root)
			check.Add(check, padBig)
			check.Mod(check, n)
			if check.Cmp(hashModN) == 0 {
				return root, padBig
			}
			// Try the alternative root: n - root
			altRoot := new(big.Int).Sub(n, root)
			check = new(big.Int).Mul(altRoot, altRoot)
			check.Add(check, padBig)
			check.Mod(check, n)
			if check.Cmp(hashModN) == 0 {
				return altRoot, padBig
			}
		}
	}
	panic("runar: RabinSign: no valid padding found within 1000 attempts")
}

// sqrtModPQ computes square root of a modulo n = p*q using CRT.
// Returns nil if no square root exists.
func sqrtModPQ(a, p, q, n *big.Int) *big.Int {
	// Compute sqrt mod p and sqrt mod q
	rp := sqrtModPrime(a, p)
	if rp == nil {
		return nil
	}
	rq := sqrtModPrime(a, q)
	if rq == nil {
		return nil
	}

	// CRT: combine rp and rq
	// result = rp * q * (q^-1 mod p) + rq * p * (p^-1 mod q) mod n
	qInvP := new(big.Int).ModInverse(q, p)
	if qInvP == nil {
		return nil
	}
	pInvQ := new(big.Int).ModInverse(p, q)
	if pInvQ == nil {
		return nil
	}

	term1 := new(big.Int).Mul(rp, q)
	term1.Mul(term1, qInvP)

	term2 := new(big.Int).Mul(rq, p)
	term2.Mul(term2, pInvQ)

	result := new(big.Int).Add(term1, term2)
	result.Mod(result, n)
	return result
}

// sqrtModPrime computes a square root of a modulo a prime p.
// Uses the Tonelli-Shanks algorithm. Returns nil if a is not a QR mod p.
func sqrtModPrime(a, p *big.Int) *big.Int {
	a = new(big.Int).Mod(a, p)
	if a.Sign() == 0 {
		return big.NewInt(0)
	}

	// Check if a is a quadratic residue using Euler's criterion
	// a^((p-1)/2) mod p must be 1
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))
	euler := new(big.Int).Exp(a, exp, p)
	if euler.Cmp(big.NewInt(1)) != 0 {
		return nil // not a QR
	}

	// Simple case: p ≡ 3 (mod 4)
	three := big.NewInt(3)
	four := big.NewInt(4)
	pMod4 := new(big.Int).Mod(p, four)
	if pMod4.Cmp(three) == 0 {
		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Div(exp, four)
		return new(big.Int).Exp(a, exp, p)
	}

	// Tonelli-Shanks
	// Factor out powers of 2 from p-1: p-1 = Q * 2^S
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	S := 0
	Q := new(big.Int).Set(pMinus1)
	for Q.Bit(0) == 0 {
		Q.Rsh(Q, 1)
		S++
	}

	// Find a non-residue z
	z := big.NewInt(2)
	for {
		euler := new(big.Int).Exp(z, exp, p)
		if euler.Cmp(pMinus1) == 0 {
			break
		}
		z.Add(z, big.NewInt(1))
	}

	M := S
	c := new(big.Int).Exp(z, Q, p)
	t := new(big.Int).Exp(a, Q, p)
	R := new(big.Int).Add(Q, big.NewInt(1))
	R.Div(R, big.NewInt(2))
	R = new(big.Int).Exp(a, R, p)

	for {
		if t.Cmp(big.NewInt(1)) == 0 {
			return R
		}
		// Find the least i such that t^(2^i) = 1 mod p
		i := 0
		tmp := new(big.Int).Set(t)
		for tmp.Cmp(big.NewInt(1)) != 0 {
			tmp.Mul(tmp, tmp)
			tmp.Mod(tmp, p)
			i++
			if i == M {
				return nil
			}
		}
		// Update
		b := new(big.Int).Set(c)
		for j := 0; j < M-i-1; j++ {
			b.Mul(b, b)
			b.Mod(b, p)
		}
		M = i
		c.Mul(b, b)
		c.Mod(c, p)
		t.Mul(t, c)
		t.Mod(t, p)
		R.Mul(R, b)
		R.Mod(R, p)
	}
}

// leBytesToBigInt interprets a byte slice as a little-endian unsigned integer.
func leBytesToBigInt(b []byte) *big.Int {
	// Reverse to big-endian
	reversed := make([]byte, len(b))
	for i, v := range b {
		reversed[len(b)-1-i] = v
	}
	return new(big.Int).SetBytes(reversed)
}

// bigIntToLEBytes converts a big.Int to little-endian unsigned bytes.
func bigIntToLEBytes(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0}
	}
	b := n.Bytes() // big-endian
	// Reverse
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// RabinSignToBytes signs a message and returns (sig, padding) as raw byte strings
// suitable for passing to VerifyRabinSig.
func RabinSignToBytes(msg []byte, p, q *big.Int) (RabinSig, ByteString) {
	sigInt, padInt := RabinSign(msg, p, q)
	return RabinSig(bigIntToLEBytes(sigInt)), ByteString(bigIntToLEBytes(padInt))
}

// RabinTestP returns the test Rabin prime p.
func RabinTestP() *big.Int {
	return new(big.Int).Set(rabinP)
}

// RabinTestQ returns the test Rabin prime q.
func RabinTestQ() *big.Int {
	return new(big.Int).Set(rabinQ)
}
