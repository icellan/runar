package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type RabinKeyPair struct {
	P *big.Int
	Q *big.Int
	N *big.Int
}

type RabinSignature struct {
	Sig     *big.Int
	Padding *big.Int
}

func generateBlumPrime(bits int) (*big.Int, error) {
	three := big.NewInt(3)
	four := big.NewInt(4)

	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}

		mod := new(big.Int).Mod(p, four)
		if mod.Cmp(three) == 0 {
			return p, nil
		}
	}
}

func GenerateRabinKeyPair() (*RabinKeyPair, error) {
	p, err := generateBlumPrime(130)
	if err != nil {
		return nil, err
	}

	var q *big.Int
	for {
		q, err = generateBlumPrime(130)
		if err != nil {
			return nil, err
		}
		if q.Cmp(p) != 0 {
			break
		}
	}

	n := new(big.Int).Mul(p, q)
	return &RabinKeyPair{P: p, Q: q, N: n}, nil
}

func num2binLE(value *big.Int, byteLen int) []byte {
	buf := make([]byte, byteLen)
	v := new(big.Int).Set(value)
	mask := big.NewInt(0xff)

	for i := 0; i < byteLen && v.Sign() > 0; i++ {
		buf[i] = byte(new(big.Int).And(v, mask).Int64())
		v.Rsh(v, 8)
	}
	return buf
}

func bufferToUnsignedLE(buf []byte) *big.Int {
	result := new(big.Int)
	for i := 0; i < len(buf); i++ {
		b := new(big.Int).SetInt64(int64(buf[i]))
		b.Lsh(b, uint(i*8))
		result.Add(result, b)
	}
	return result
}

func isQR(x, p *big.Int) bool {
	mod := new(big.Int).Mod(x, p)
	if mod.Sign() == 0 {
		return true
	}

	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))
	result := new(big.Int).Exp(mod, exp, p)
	return result.Cmp(big.NewInt(1)) == 0
}

func crt(sp, sq, p, q *big.Int) *big.Int {
	n := new(big.Int).Mul(p, q)

	qInvP := new(big.Int).ModInverse(q, p)
	pInvQ := new(big.Int).ModInverse(p, q)

	t1 := new(big.Int).Mul(sp, q)
	t1.Mul(t1, qInvP)
	t1.Mod(t1, n)

	t2 := new(big.Int).Mul(sq, p)
	t2.Mul(t2, pInvQ)
	t2.Mod(t2, n)

	result := new(big.Int).Add(t1, t2)
	result.Mod(result, n)
	if result.Sign() < 0 {
		result.Add(result, n)
	}
	return result
}

func RabinSign(msgBytes []byte, keypair *RabinKeyPair) (*RabinSignature, error) {
	p := keypair.P
	q := keypair.Q
	n := keypair.N

	h := sha256.Sum256(msgBytes)
	hInt := bufferToUnsignedLE(h[:])

	for pad := int64(0); pad < 1000; pad++ {
		padBig := big.NewInt(pad)

		target := new(big.Int).Sub(hInt, padBig)
		target.Mod(target, n)
		if target.Sign() < 0 {
			target.Add(target, n)
		}

		if !isQR(target, p) || !isQR(target, q) {
			continue
		}

		pExp := new(big.Int).Add(p, big.NewInt(1))
		pExp.Div(pExp, big.NewInt(4))
		sp := new(big.Int).Exp(new(big.Int).Mod(target, p), pExp, p)

		qExp := new(big.Int).Add(q, big.NewInt(1))
		qExp.Div(qExp, big.NewInt(4))
		sq := new(big.Int).Exp(new(big.Int).Mod(target, q), qExp, q)

		sig := crt(sp, sq, p, q)

		check := new(big.Int).Mul(sig, sig)
		check.Add(check, padBig)
		check.Mod(check, n)
		if check.Cmp(hInt) == 0 {
			return &RabinSignature{Sig: sig, Padding: padBig}, nil
		}

		sigAlt := new(big.Int).Sub(n, sig)
		check = new(big.Int).Mul(sigAlt, sigAlt)
		check.Add(check, padBig)
		check.Mod(check, n)
		if check.Cmp(hInt) == 0 {
			return &RabinSignature{Sig: sigAlt, Padding: padBig}, nil
		}
	}

	return nil, fmt.Errorf("failed to generate Rabin signature (no QR found within 1000 padding values)")
}

func FindSignableOutcome(target int64, keypair *RabinKeyPair) (int64, *RabinSignature, error) {
	for offset := int64(0); offset <= 10000; offset++ {
		candidates := []int64{target}
		if offset > 0 {
			candidates = []int64{target + offset, target - offset}
		}

		for _, val := range candidates {
			if val <= 0 {
				continue
			}

			msgBytes := num2binLE(big.NewInt(val), 8)

			h := sha256.Sum256(msgBytes)
			lastByte := h[31]
			if lastByte == 0 || lastByte >= 0x80 {
				continue
			}

			sig, err := RabinSign(msgBytes, keypair)
			if err != nil {
				continue
			}
			return val, sig, nil
		}
	}

	return 0, nil, fmt.Errorf("could not find a signable outcome near %d", target)
}
