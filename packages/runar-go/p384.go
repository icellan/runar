// P-384 (NIST P-384 / secp384r1) off-chain helpers for testing Rúnar contracts.
//
// These functions use Go's standard library crypto/ecdsa and crypto/elliptic
// with no external dependencies. They are not compiled into Bitcoin Script —
// they exist so Go contract tests can generate keys, sign messages, and
// perform EC arithmetic using the P-384 curve.
//
// P384Point is a 96-byte ByteString: x[48] || y[48], big-endian, zero-padded.
// Coordinates are 48 bytes each (384 bits).
package runar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// P384Point is a 96-byte ByteString encoding a P-384 point as x[48] || y[48].
// Coordinates are big-endian and zero-padded to 48 bytes each.
type P384Point = ByteString

// P384KeyPair holds a P-384 key pair.
type P384KeyPair struct {
	SK           *ecdsa.PrivateKey
	PK           P384Point // 96-byte uncompressed encoding (x[48] || y[48])
	PKCompressed []byte    // 49-byte compressed encoding (02/03 prefix + x[48])
}

// p384PointFromXY serializes a P-384 (x, y) pair into a 96-byte P384Point.
func p384PointFromXY(x, y *big.Int) P384Point {
	buf := make([]byte, 96)
	xb := x.Bytes()
	yb := y.Bytes()
	copy(buf[48-len(xb):48], xb)
	copy(buf[96-len(yb):96], yb)
	return P384Point(buf)
}

// p384XYFromPoint extracts (x, y) *big.Int from a 96-byte P384Point.
func p384XYFromPoint(p P384Point) (*big.Int, *big.Int) {
	b := []byte(p)
	if len(b) != 96 {
		panic("runar: P384Point must be exactly 96 bytes")
	}
	x := new(big.Int).SetBytes(b[:48])
	y := new(big.Int).SetBytes(b[48:])
	return x, y
}

// P384Keygen generates a random P-384 key pair.
func P384Keygen() P384KeyPair {
	sk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic("runar: P384Keygen: " + err.Error())
	}
	pk := p384PointFromXY(sk.PublicKey.X, sk.PublicKey.Y)
	compressed := elliptic.MarshalCompressed(elliptic.P384(), sk.PublicKey.X, sk.PublicKey.Y)
	return P384KeyPair{
		SK:           sk,
		PK:           pk,
		PKCompressed: compressed,
	}
}

// P384Sign signs msg with sk using ECDSA on P-384.
// The message is SHA-256 hashed internally before signing.
// Returns a 96-byte raw signature: r[48] || s[48] (big-endian, zero-padded).
func P384Sign(msg []byte, sk *ecdsa.PrivateKey) []byte {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, sk, digest[:])
	if err != nil {
		panic("runar: P384Sign: " + err.Error())
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	return sig
}

// P384Add adds two P-384 points.
// If either point is the zero point (all-zero bytes), the other is returned.
func P384Add(a, b P384Point) P384Point {
	ax, ay := p384XYFromPoint(a)
	bx, by := p384XYFromPoint(b)
	curve := elliptic.P384()
	rx, ry := curve.Add(ax, ay, bx, by)
	return p384PointFromXY(rx, ry)
}

// P384Mul performs scalar multiplication k * p on the P-384 curve.
func P384Mul(p P384Point, k *big.Int) P384Point {
	px, py := p384XYFromPoint(p)
	curve := elliptic.P384()
	kBytes := k.Bytes()
	rx, ry := curve.ScalarMult(px, py, kBytes)
	return p384PointFromXY(rx, ry)
}

// P384MulGen performs scalar multiplication k * G where G is the P-384 generator.
func P384MulGen(k *big.Int) P384Point {
	curve := elliptic.P384()
	kBytes := k.Bytes()
	rx, ry := curve.ScalarBaseMult(kBytes)
	return p384PointFromXY(rx, ry)
}

// P384Negate returns the negation of a P-384 point: (x, p - y).
func P384Negate(p P384Point) P384Point {
	px, py := p384XYFromPoint(p)
	fieldP := elliptic.P384().Params().P
	negY := new(big.Int).Sub(fieldP, py)
	negY.Mod(negY, fieldP)
	return p384PointFromXY(px, negY)
}

// P384OnCurve reports whether the given point lies on the P-384 curve.
func P384OnCurve(p P384Point) bool {
	px, py := p384XYFromPoint(p)
	// Reject the point at infinity (0, 0) — not a valid curve point.
	if px.Sign() == 0 && py.Sign() == 0 {
		return false
	}
	return elliptic.P384().IsOnCurve(px, py)
}

// P384EncodeCompressed returns the 49-byte compressed encoding of a P-384 point
// (02/03 prefix byte followed by the 48-byte x coordinate, big-endian).
func P384EncodeCompressed(p P384Point) ByteString {
	px, py := p384XYFromPoint(p)
	compressed := elliptic.MarshalCompressed(elliptic.P384(), px, py)
	return ByteString(compressed)
}

// VerifyECDSAP384 verifies a raw ECDSA signature on P-384.
// msg is the raw message — it is SHA-256 hashed internally before verification.
// sig is the 96-byte raw signature (r[48] || s[48]) produced by P384Sign.
// pubkey is the 49-byte compressed public key (02/03 + x[48]).
func VerifyECDSAP384(msg, sig, pubkey ByteString) bool {
	if len(sig) != 96 {
		return false
	}
	digest := sha256.Sum256([]byte(msg))

	// Decode compressed public key.
	x, y := elliptic.UnmarshalCompressed(elliptic.P384(), []byte(pubkey))
	if x == nil {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}

	r := new(big.Int).SetBytes([]byte(sig)[:48])
	s := new(big.Int).SetBytes([]byte(sig)[48:])
	return ecdsa.Verify(pub, digest[:], r, s)
}
