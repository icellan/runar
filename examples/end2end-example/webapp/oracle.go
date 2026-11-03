package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// F-162 (CL-BUG-255) — the price oracle that settles a round.
//
// The webapp used to bake `oraclePubKey = 12345` into every PriceBet and spend
// through `cancel`, so the oracle-settlement path it advertises never ran. A
// 12345 modulus is also no key at all: verifyRabinSig reduces the digest mod
// the key, so `sig = 0, padding = SHA256(msg) mod 12345` passes for any price,
// signed by nobody. Each game now owns a real Rabin key whose factors only this
// process holds, and the round is settled with the oracle's signature.
//
// Same scheme as packages/runar-go RabinSign and webapp-blackjack/rabin.go:
// h = SHA256(msg) as an unsigned little-endian integer, and the signature is
// (sig, padding) with (sig^2 + padding) mod n == h mod n.

// rabinPrimeBits sizes each Blum prime. 2 x 136 bits gives a ~272-bit modulus,
// larger than any SHA-256 digest (the conformance witness uses ~2^260).
const rabinPrimeBits = 136

type RabinKey struct {
	P, Q, N *big.Int
}

func generateBlumPrime(bits int) (*big.Int, error) {
	three, four := big.NewInt(3), big.NewInt(4)
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		if new(big.Int).Mod(p, four).Cmp(three) == 0 {
			return p, nil
		}
	}
}

func newRabinKey() (*RabinKey, error) {
	p, err := generateBlumPrime(rabinPrimeBits)
	if err != nil {
		return nil, err
	}
	for {
		q, err := generateBlumPrime(rabinPrimeBits)
		if err != nil {
			return nil, err
		}
		if q.Cmp(p) != 0 {
			return &RabinKey{P: p, Q: q, N: new(big.Int).Mul(p, q)}, nil
		}
	}
}

// leUnsigned reads b as an unsigned little-endian integer.
func leUnsigned(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

// leBytes is the unsigned little-endian encoding of a non-negative v (empty for 0).
func leBytes(v *big.Int) []byte {
	be := v.Bytes()
	out := make([]byte, len(be))
	for i := range be {
		out[len(be)-1-i] = be[i]
	}
	return out
}

// priceMessage is what PriceBet.settle verifies: num2bin(price, 8).
func priceMessage(price int64) []byte {
	return num2bin8(big.NewInt(price))
}

func num2bin8(v *big.Int) []byte {
	out := make([]byte, 8)
	copy(out, leBytes(v))
	return out
}

// sign returns (sig, padding) for msg. Both factors are Blum primes, so a
// square root mod each is a single exponentiation.
func (k *RabinKey) sign(msg []byte) (sig, padding *big.Int, err error) {
	h := sha256.Sum256(msg)
	hModN := new(big.Int).Mod(leUnsigned(h[:]), k.N)
	expP := new(big.Int).Rsh(new(big.Int).Add(k.P, big.NewInt(1)), 2)
	expQ := new(big.Int).Rsh(new(big.Int).Add(k.Q, big.NewInt(1)), 2)
	qInvP := new(big.Int).ModInverse(k.Q, k.P)
	pInvQ := new(big.Int).ModInverse(k.P, k.Q)

	for pad := int64(0); pad < 1000; pad++ {
		target := new(big.Int).Sub(hModN, big.NewInt(pad))
		target.Mod(target, k.N)
		sp := new(big.Int).Exp(new(big.Int).Mod(target, k.P), expP, k.P)
		sq := new(big.Int).Exp(new(big.Int).Mod(target, k.Q), expQ, k.Q)
		// CRT: s = sp*q*(q^-1 mod p) + sq*p*(p^-1 mod q) mod n
		s := new(big.Int).Mul(sp, k.Q)
		s.Mul(s, qInvP)
		t := new(big.Int).Mul(sq, k.P)
		t.Mul(t, pInvQ)
		s.Add(s, t).Mod(s, k.N)

		check := new(big.Int).Mul(s, s)
		check.Add(check, big.NewInt(pad)).Mod(check, k.N)
		if check.Cmp(hModN) == 0 {
			return s, big.NewInt(pad), nil
		}
	}
	return nil, nil, fmt.Errorf("rabin sign: no padding < 1000 yields a quadratic residue")
}
